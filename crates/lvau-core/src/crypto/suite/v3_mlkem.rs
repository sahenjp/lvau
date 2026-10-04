use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use lvau_protocol::envelope_v3::{
    V3MutableMlKem768Slot, V3_MLKEM768_CIPHERTEXT_SIZE, V3_MUTABLE_SLOT_MLKEM768,
};
use ml_kem::{
    kem::{Decapsulate, Encapsulate, KeyExport},
    DecapsulationKey768, EncapsulationKey768,
};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::CryptoError;

const KEY_ID_DOMAIN: &[u8] = b"Lvau v3 A4 recipient key ID\0";
const WRAPPING_DOMAIN: &[u8] = b"Lvau v3 A4 ML-KEM root wrapping\0";
const WRAP_KEY_INFO_DOMAIN: &[u8] = b"Lvau v3 A4 ML-KEM wrap key\0";
const WRAP_AAD_DOMAIN: &[u8] = b"Lvau v3 A4 ML-KEM root-wrap AAD\0";

pub fn recipient_key_id(public: &EncapsulationKey768) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(KEY_ID_DOMAIN);
    hash.update([V3_MUTABLE_SLOT_MLKEM768]);
    hash.update(public.to_bytes());
    hash.finalize().into()
}

fn derive_wrapping_key(
    shared_secret: &[u8],
    context: &[u8; 32],
    key_id: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(WRAPPING_DOMAIN), shared_secret);
    let mut info = Vec::with_capacity(WRAP_KEY_INFO_DOMAIN.len() + context.len() + key_id.len());
    info.extend_from_slice(WRAP_KEY_INFO_DOMAIN);
    info.extend_from_slice(context);
    info.extend_from_slice(key_id);

    let mut wrapping_key = Zeroizing::new([0; 32]);
    hk.expand(&info, &mut *wrapping_key)
        .map_err(|_| CryptoError::EncryptionFailed)?;
    Ok(wrapping_key)
}

fn wrap_aad(
    context: &[u8; 32],
    key_id: &[u8; 32],
    encapsulation_ciphertext: &[u8; V3_MLKEM768_CIPHERTEXT_SIZE],
    nonce: &[u8; 24],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(
        WRAP_AAD_DOMAIN.len()
            + context.len()
            + key_id.len()
            + encapsulation_ciphertext.len()
            + nonce.len(),
    );
    aad.extend_from_slice(WRAP_AAD_DOMAIN);
    aad.extend_from_slice(context);
    aad.extend_from_slice(key_id);
    aad.extend_from_slice(encapsulation_ciphertext);
    aad.extend_from_slice(nonce);
    aad
}

pub fn wrap_root_key(
    root: &[u8; 32],
    public: &EncapsulationKey768,
    context: &[u8; 32],
) -> Result<V3MutableMlKem768Slot, CryptoError> {
    let key_id = recipient_key_id(public);
    let (ciphertext, mut shared_secret) = public.encapsulate();
    let wrapping_key = derive_wrapping_key(shared_secret.as_slice(), context, &key_id);
    shared_secret.as_mut_slice().zeroize();
    let wrapping_key = wrapping_key?;

    let encapsulation_ciphertext = ciphertext
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::EncryptionFailed)?;
    let mut wrapping_nonce = [0; 24];
    OsRng.fill_bytes(&mut wrapping_nonce);
    let aad = wrap_aad(context, &key_id, &encapsulation_ciphertext, &wrapping_nonce);
    let cipher = XChaCha20Poly1305::new(wrapping_key.as_ref().into());
    let encrypted_file_root_key = cipher
        .encrypt(
            &XNonce::from(wrapping_nonce),
            Payload {
                msg: root,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::EncryptionFailed)?
        .try_into()
        .map_err(|_| CryptoError::EncryptionFailed)?;

    Ok(V3MutableMlKem768Slot {
        key_id,
        encapsulation_ciphertext: Box::new(encapsulation_ciphertext),
        wrapping_nonce,
        encrypted_file_root_key,
    })
}

pub fn unwrap_root_key(
    private: &DecapsulationKey768,
    slot: &V3MutableMlKem768Slot,
    context: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    if recipient_key_id(private.encapsulation_key()) != slot.key_id {
        return Err(CryptoError::DecryptionFailed);
    }

    let mut shared_secret = private
        .decapsulate_slice(slot.encapsulation_ciphertext.as_ref().as_slice())
        .map_err(|_| CryptoError::DecryptionFailed)?;
    let wrapping_key = derive_wrapping_key(shared_secret.as_slice(), context, &slot.key_id);
    shared_secret.as_mut_slice().zeroize();
    let wrapping_key = wrapping_key.map_err(|_| CryptoError::DecryptionFailed)?;
    let aad = wrap_aad(
        context,
        &slot.key_id,
        &slot.encapsulation_ciphertext,
        &slot.wrapping_nonce,
    );
    let cipher = XChaCha20Poly1305::new(wrapping_key.as_ref().into());
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                &XNonce::from(slot.wrapping_nonce),
                Payload {
                    msg: &slot.encrypted_file_root_key,
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::DecryptionFailed)?,
    );
    let mut root = Zeroizing::new([0; 32]);
    root.copy_from_slice(&plaintext);
    Ok(root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::generate_keypair;

    fn decode_hex(value: &str) -> Vec<u8> {
        let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
        assert!(remainder.is_empty());
        pairs
            .iter()
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    #[test]
    fn mlkem_768_encapsulation_matches_nist_acvp_vector() {
        let encapsulation_key = decode_hex(concat!(
            "89D2CB65F94DCBFC890EFC7D0E5A7A38344D1641A3D0B024D50797A5F23C3A18",
            "B3101A1269069F43A842BACC098A8821271C673DB1BEB33034E4D7774D16635C",
            "7C2C3C2763453538BC1632E1851591A51642974E5928ABB8E55FE55612F9B141",
            "AFF015545394B2092E590970EC29A7B7E7AA1FB4493BF7CB731906C2A5CB49E",
            "6614859064E19B8FA26AF51C44B5E7535BFDAC072B646D3EA490D277F0D97CE",
            "D47395FED91E8F2BCE0E3CA122C2025F74067AB928A822B35653A74F0675762",
            "9AFB1A1CAF237100EA935E793C8F58A71B3D6AE2C8658B10150D4A38F572A0D",
            "49D28AE89451D338326FDB3B4350036C1081117740EDB86B12081C5C1223DBB5",
            "660D5B3CB3787D481849304C68BE875466F14EE5495C2BD795AE412D09002D6",
            "5B8719B90CBA3603AC4958EA03CC138C86F7851593125334701B677F82F4952",
            "A4C93B5B4C134BB42A857FD15C650864A6AA94EB691C0B691BE4684C1F5B7490",
            "467FC01B1D1FDA4DDA35C4ECC231BC73A6FEF42C99D34EB82A4D014987B3E386",
            "910C62679A118F3C5BD9F467E4162042424357DB92EF484A4A1798C1257E870",
            "A30CB20AAA0335D83314FE0AA7E63A862648041A72A6321523220B1ACE9BB701",
            "B21AC1253CB812C15575A9085EABEADE73A4AE76E6A7B158A20586D78A5AC620",
            "A5C9ABCC9C043350A73656B0ABE822DA5E0BA76045FAD75401D7A3B703791B7E",
            "99261710F86B72421D240A347638377205A152C794130A4E047742B888303BDDC",
            "309116764DE7424CEBEA6DB65348AC537E01A9CC56EA667D5AA87AC9AAA4317D",
            "262C10143050B8D07A728CA633C13E468ABCEAD372C77B8ECF3B986B98C1E558",
            "60B2B4216766AD874C35ED7205068739230220B5A2317D102C598356F168ACBE806",
            "08DE4C9A710B8DD07078CD7C671058AF1B0B8304A314F7B29BE78A933C7B929442",
            "4954A1BF8BC745DE86198659E0E1225A910726074969C39A97C19240601A46E013",
            "DCDCB677A8CBD2C95A40629C256F24A328951DF57502AB30772CC7E5B850027",
            "C8551781CE4985BDACF6B865C104E8A4BC65C41694D456B7169E45AB3D7ACABE",
            "AFE23AD6A7B94D1979A2F4C1CAE7CD77D681D290B5D8E451BFDCCCF5310B9D12",
            "A88EC29B10255D5E17A192670AA9731C5CA67EC784C502781BE8527D6FC003C",
            "6701B3632284B40307A527C7620377FEB0B73F722C9E3CD4DEC64876B93AB5B",
            "7CFC4A657F852B659282864384F442B22E8A21109387B8B47585FC680D0BA45",
            "C7A8B1D7274BDA57845D100D0F42A3B74628773351FD7AC305B2497639BE90B3",
            "F4F71A6AA3561EECC6A691BB5CB3914D8634CA1E1AF543C049A8C6E868C51F0",
            "423BD2D5AE09B79E57C27F3FE3AE2B26A441BABFC6718CE8C05B4FE793B910B",
            "8FBCBBE7F1013242B40E0514D0BDC5C88BAC594C794CE5122FBF34896819147",
            "B928381587963B0B90034AA07A10BE176E01C80AD6A4B71B10AF4241400A2A4C",
            "BBC05961A15EC1474ED51A3CC6D35800679A462809CAA3AB4F7094CD6610B4A700",
            "CBA939E7EAC93E38C99755908727619ED76A34E53C4FA25BFC97008206697DD145",
            "E5B9188E5B014E941681E15FE3E132B8A3903474148BA28B987111C9BCB3989BBBC",
            "671C581B44A492845F288E62196E471FED3C39C1BBDDB0837D0D4706B0922C4"
        ));
        let encapsulation_key: [u8; 1184] = encapsulation_key.try_into().unwrap();
        let encapsulation_key = EncapsulationKey768::new(&encapsulation_key.into()).unwrap();
        let message: [u8; 32] =
            decode_hex("2CE74AD291133518FE60C7DF5D251B9D82ADD48462FF505C6E547E949E6B6BF7")
                .try_into()
                .unwrap();
        let message: ml_kem::B32 = message.into();

        let (ciphertext, shared_secret) = encapsulation_key.encapsulate_deterministic(&message);

        assert_eq!(
            ciphertext.as_slice(),
            decode_hex(concat!(
                "56B42D593AAB8E8773BD92D76EABDDF3B1546F8326F57A7B773764B6C0DD3047",
                "0F68DFF82E0DCA92509274ECFE83A954735FDE6E14676DAAA3680C30D524F4E",
                "FA79ED6A1F9ED7E1C00560E8683538C3105AB931BE0D2B249B38CB9B13AF5CEA",
                "F7887A59DBA16688A7F28DE0B14D19F391EB41832A56479416CCF94E997390E",
                "D7878EEAFF49328A70E0AB5FCE6C63C09B35F4E45994DE615B88BB722F70E87",
                "D2BBD72AE71E1EE9008E459D8E743039A8DDEB874FCE5301A2F8C0EE8C2FEE7",
                "A4EE68B5ED6A6D9AB74F98BB3BA0FE89E82BD5A525C5E8790F818CCC605877D",
                "46C8BDB5C337B025BB840FF471896E43BFA99D73DBE31805C27A43E57F0618B",
                "3AE522A4644E0D4E4C1C548489431BE558F3BFC50E16617E110DD7AF9A6FD83",
                "E3FBB68C304D15F6CB700D61D7AA915A6751EA3BA80223E654132A20999A43BF",
                "408592730B9A9499636C09FA729F9CB1F9D3442F47357A2B9CF15D3103B9BF396",
                "C23088F118EDE346B5C03891CFA5D517CEF8471322E7E31087C4B036ABAD784B",
                "FF72A9B11FA198FACBCB91F067FEAF76FCFE5327C1070B3DA6988400756760D2",
                "D1F060298F1683D51E3616E98C51C9C03AA42F2E633651A47AD3CC2AB4A852AE",
                "0C4B04B4E1C3DD944445A2B12B4F42A6435105C04122FC3587AFE409A00B308D",
                "63C5DD8163654504EEDBB7B5329577C35FBEB3F463872CAC28142B3C12A740EC",
                "6EA7CE9AD78C6FC8FE1B4DF5FC55C1667F31F2312DA07799DC870A478608549",
                "FEDAFE021F1CF2984180364E90AD98D845652AA3CDD7A8EB09F5E51423FAB42A",
                "7B7BB4D514864BE8D71297E9C3B17A993F0AE62E8EF52637BD1B885BD9B6AB727",
                "854D703D8DC478F96CB81FCE4C60383AC01FCF0F971D4C8F352B7A82E218652",
                "F2C106CA92AE686BACFCEF5D327347A97A9B375D67341552BC2C538778E0F980",
                "1823CCDFCD1EAADED55B18C9757E3F212B2889D3857DB51F981D16185FD0F900",
                "853A75005E3020A8B95B7D8F2F2631C70D78A957C7A62E1B3719070ACD1FD480",
                "C25B83847DA027B6EBBC2EEC2DF22C87F9B46D5D7BAF156B53CEE929572B92C",
                "4784C4E829F3446A1FFE47F99DECD0436029DDEBD3ED8E87E5E73D123DBE8A4D",
                "DACF2ABDE87F33AE2B621C0EC5D5CAD1259DEEC2AEFF6088F04F27A20338B576",
                "2543E5100899A4CBFB7B3CA456B3A19B83A4C432230C23E1C7F107C4CB112152",
                "F1C0F30DA0BB33F4F11F47EEA43872BAFA84AE22256D708E0604DADE4B2A4DDE",
                "8CCCF11930E13553934AE3ECE52F3D7CCC00287377879FE6B8ECE7EF79423507",
                "C9DA339559C20DE1C51955999BAE47401DC3CDFAA1B256D09C7DB9FC8698BFCE",
                "FA7302D56FBCDE1FBAAA1C653454E6FD3D84E4F79A931C681CBB6CB462B10DAE",
                "112BDFB7F65C7FDF6E5FC594EC3A474A94BD97E6EC81F71C230BF70CA0F13CE",
                "3DFFBD9FF9804EFD8F37A4D3629B43A8F55544EBC5AC0ABD9A33D7969906834",
                "6A0F1A3A96E115A5D80BE165B562D082984D5AACC3A2301981A6418F8BA7D7B0",
                "D7CA5875C6"
            ))
        );
        assert_eq!(
            shared_secret.as_slice(),
            decode_hex("2696D28E9C61C2A01CE9B1608DCB9D292785A0CD58EFB7FE13B1DE95F0DB55B3")
        );
    }

    #[test]
    fn key_id_is_key_and_algorithm_separated() {
        let (_, public_a) = generate_keypair();
        let (_, public_b) = generate_keypair();
        let key_id = recipient_key_id(&public_a.mlkem);

        assert_ne!(key_id, recipient_key_id(&public_b.mlkem));

        let mut other_algorithm = Sha256::new();
        other_algorithm.update(KEY_ID_DOMAIN);
        other_algorithm.update([V3_MUTABLE_SLOT_MLKEM768 - 1]);
        other_algorithm.update(public_a.mlkem.to_bytes());
        assert_ne!(key_id, <[u8; 32]>::from(other_algorithm.finalize()));
    }

    #[test]
    fn generated_hybrid_mlkem_key_wraps_and_opens_root() {
        let (private, public) = generate_keypair();
        let root = [0x42; 32];
        let context = [0xA4; 32];

        let slot = wrap_root_key(&root, &public.mlkem, &context).unwrap();

        assert_eq!(slot.encapsulation_ciphertext.len(), 1088);
        assert_eq!(
            *unwrap_root_key(&private.mlkem, &slot, &context).unwrap(),
            root
        );
    }

    #[test]
    fn wrong_key_and_authenticated_slot_mutations_fail() {
        let (private, public) = generate_keypair();
        let (wrong_private, _) = generate_keypair();
        let context = [0x34; 32];
        let slot = wrap_root_key(&[0x12; 32], &public.mlkem, &context).unwrap();

        assert!(matches!(
            unwrap_root_key(&wrong_private.mlkem, &slot, &context),
            Err(CryptoError::DecryptionFailed)
        ));

        let mut changed = slot.clone();
        changed.key_id[0] ^= 1;
        assert!(matches!(
            unwrap_root_key(&private.mlkem, &changed, &context),
            Err(CryptoError::DecryptionFailed)
        ));

        let mut changed = slot.clone();
        changed.encapsulation_ciphertext[0] ^= 1;
        assert!(matches!(
            unwrap_root_key(&private.mlkem, &changed, &context),
            Err(CryptoError::DecryptionFailed)
        ));

        let mut changed = slot;
        changed.encrypted_file_root_key[0] ^= 1;
        assert!(matches!(
            unwrap_root_key(&private.mlkem, &changed, &context),
            Err(CryptoError::DecryptionFailed)
        ));
    }

    #[test]
    fn correct_length_malformed_ciphertext_reaches_implicit_rejection() {
        let (private, public) = generate_keypair();
        let context = [0x56; 32];
        let mut slot = wrap_root_key(&[0x78; 32], &public.mlkem, &context).unwrap();
        *slot.encapsulation_ciphertext = [0; V3_MLKEM768_CIPHERTEXT_SIZE];

        assert!(private
            .mlkem
            .decapsulate_slice(slot.encapsulation_ciphertext.as_ref().as_slice())
            .is_ok());
        assert!(matches!(
            unwrap_root_key(&private.mlkem, &slot, &context),
            Err(CryptoError::DecryptionFailed)
        ));
    }
}
