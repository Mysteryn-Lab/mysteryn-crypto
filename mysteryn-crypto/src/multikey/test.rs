use super::{MultikeyPublicKey, MultikeySecretKey};
use crate::{
    attributes::SignatureAttributes,
    did::{PublicDidTrait, SecretDidTrait},
    key_traits::*,
    multicodec::{known_algorithm_name, multicodec_prefix},
    result::Result,
};
use mysteryn_keys::DefaultKeyFactory;
use std::str::FromStr;
#[cfg(all(target_family = "wasm", target_os = "unknown"))]
use wasm_bindgen_test::wasm_bindgen_test;

type PublicKey = MultikeyPublicKey<DefaultKeyFactory>;
type SecretKey = MultikeySecretKey<DefaultKeyFactory>;

// Ed25519
const SECRET1: &str = "secret_xahgjgqfsxwdjkxun9wspqzgphh3z0t2xdh3ggmmjry3xuf4rs6y7yv8q0lers9220mmgk7nc9z58qxur4v2q0t9lx2kr6zps";
const PUBLIC1: &str =
    "pub_xahgjw6qgrwp6kyqgpyzqnvfy45r2uwct508t4lfxfnp6uve2zgw7p8mtyan0dnlyra6k36vrqq7e5q90t6v";
// P521
const SECRET2: &str = "secret_xahgjgsfsxwdjkxun9wspqzsspxhve2qvrqxkvhhpf9jgz80qjtardf2xjd9jaqeq5sf2nt87hpsc5z3y0k4mjsnf82syjwwzpmujzn9zy87tux24rwmmm4ekkt0u6l88ypcphqatzapfkc8h7khy9y";
const PUBLIC2: &str = "pub_xahgjgyfqrwp6kyqgpgvpqrfjk9lu7lr2qvtskpafj8ef5yxdwwc6t55w9wuwdfzrpk5luvvckxplq89qd4dww2cqudpm7r2h8dtxr3kpjw60unrnrvtumc7kdprgnhht93zyfsjs5dg";
// Falcon-512
const SECRET3: &str = "secret_xahgjqqpnnv43hyet5qsqczzjez0er69asgrea7qhmm6qqsqfhq3g5rlqqh847lplm5q7qctm7rsqtauawstv27lsreuplqtn7qssn7qzlqtuzpqqy87zp8mcyqssyt7lzhlurplcvrlasqypezlsyzz7q8lm7l7lmuql7ssflpqc86ra08vzgpsq0nu6qgurlq7qt5zu7qgr7q0ht6zzqqswzq0gqypz0csxryw0cvyrqhl7zassgplr78lwplscyzplsgcp7rl0lh7qjsnuzzlcrmualsg2rqql5p4zqcrc9z0s8uyq3kuz9uq8m0aydluraqs08uqlwsmm5u305yypll5f6ywhn7pr0hmkzppqlmuqqgczz7s0t6rrzggypqllh6ppsh5wp7pg8mlzl8g97qlku9alwctlu7l85rupsgcrullst5z70c87p77ly07uwcyy9yl8uqqy0qq97zqqg5qmssgfll0ctkqp3pg9mq3qtahl70sgpl7kmuqqssy2pupqru9zlcr7970cgp770gt3lqskla7lsqsrmy7cvyrqschnm7sq8eeplfgwzps80czl38l5ppq8l7rq50uyp7s3yzpzpqtnh6q0murpq3ypaallvy8qphmalzqscrll0kmm673csvpr0sr6paqsgr7rssgpmqlhgq8a38sxqupg86y9lgydm7s0l58aqh5rlpssv8m7sfqraplhygpal0cqqps0c9maqslupz7hsd7y3c5zyq38spapqghlmqqgmvralcrharlg0hly3srwpz0l5rcpl0c8lq3slaazwhraulq05f7730v8uz0c84k7shuqxqqgsxqpsqgzrp0c8duqqgqfl7lggyplpqyqqzqlu8aqqqc87zsgqxpl3chlaalcteelqc5yqqqctlul3s52p70sgvppshu2zq38gzyzqs0luq7lc29m0qh6qr7gq37u3glauql8halrqlhlllsgvpapsq0hll7hsyq7pqh37l7svplqshsqpr00vqqqq85sr70clc9q0hmwgqlctlmrq0l47llcvr7pqfrnapslmm7qqgqz9qqlyxxms8cqqlpq86qlsgg3llssqr7q0h5t7zqqygp7l8ss97lqqx9qlcvrmzl05yrppg8mll0lcrulsqgyyq7qvzym3qgr67p8uqqlqhcwrl7lv96qlg8elpq8sygzs85phaw8csppsqrlur7hcwzlpq8hlpscme6lplma6qscs0apx7us3c80upyqdjvhsmnapqgw67qqs2zqnzsjq3mclz5936x0jpn60czg5rcf0necy7vf0dll39gy0xph2lq53t53wmnm3367epuuj97sna5xm7pkwzhmq5yq27m6l9k8n75jaru0fmsvzg9sq9ruq6pwsqgx39u347nszm6h4q0e0szpylszp97sqpt3lha0yuguqw8hlus4l9acxay238l0x9gg3ace8lqxl7f3z9l97kzxnunk0g9hcpt7a3clxlmcqyrhs75v7ae8wa5x39hlvqs905qstq5qwdleg78ad86x7lmkamhqepmkqv8q28h6qj9c2pqqq4ch4p58quxkh28k6hccflluqduhpynllqz04zu9qe7s7pnc74eh9qqf7k9c0rrsl06srptu3qys6mnh3lk76xhwsnalhpq9q4mf0z8fs8alsxgtmajfhqu5jj8h9l0d72yw6phusa6p7um6dh7xwlg27cxewz0v00asgy53l6p3p9mtss8l5rfpqdeh2myd7xz7t90rl2t8m78krnkp3lg875geg75q3eegjcvysg9lfenjq6zwd65r34a0ylvnsh7qyrq80xzgzlt7pjzcvalcpv98cp80q0kg0lhhjc9qfmm67mmhxpcjl96wt7lm3wq8hlgy06rq2lu53ypsdp53aq8hfay30cqhvzvypv902lv3dd6c5ar3lwg02xvxwmh04mvrl7zqexcxv0mg57v3l0mqgalk746wglmkq5p0ue8mppesvrtap5xl4lrls2r3vxr73yrhcll770lc98lcwvykvzq8lmuqjps9yvctvvdhkutf4xyeq6qgppcphqatzvpnflx08jfkgls033v4jqmerru37muwkdr8n6z27ypr2wstarmn7tujvela8wc5dsj7zuudkny7qx";
const PUBLIC3: &str = "pub_xahgjqqqmsw43qyqvpquymmty2c2p497dgae0x9mk4tyjfjmtm83vnayh29ju2le6wk2gackjlr0w5dgsgjysvnqt24837p7gmdumzcesfgz9udz3kur5f4yjdpm7gw2r9d776n22xn0ywy7pfp22q2cxn4vfqyj0jpr0a22te9zfqqyck2mvqajm8ctk8sqg2u736kgt4xew2wuwkwusnehnzft8jq3cc5a6e9mz6ykvwa240q5aeatdv80k2d92ca9agtl7d3qsayquedq874pssvy5k7q6xgwjcecwe9h839adxqekqq44hjhxttfkmuvswdsxsfshect9uc5djafen99ptuq0kmcs8pdpygxfdxf2tschwvls98950vvpnts4a5t368znnkc3aqu30sdmp4w7etthn7m8azkspmr8thtfque2djvs4aqje53y358646h5228yksqrvadtknltwrgpalvrrm3s5hnkp4jrxjjw9zgneqj3dm4zydsm30x7yvzzgg5027qds7f3dzrt9afjxnqzmssfeflyzdrrkvrgfyqdh86m6vsg5se40d6uxmu0kqtu40ec5w6t04kxmgde067e5mp4ljdlzm5gwjq398eetkqj9pfdzelf8vc94e04wh3ay4egtvd039gq5sc3yeq2xz0g6d69y9pk7hyyxvjrq6rqmv3m5x52ulycg57k73xlct952r0j4hte58uts35nv2uwa47sn4rve5qglxwaq3cpyrjs6n4kkw9syccpz8g3xrfm5h0f5q8qxxg76l96en9mje5wqfwgztqvsqxze5w8qy70gzrdjj3wts8c759gnnmzkhlsvae4pac3m5d3dxrw6zt957pjakk6gkswgs466e4sqvyqzucp5z8gf3zadv7hh3dktfsy4r26skv5pc36kvwpdawp8jcjzuujgwus2z9zx6yu2qsc3cxgsjg0432zr6047swn2uk8jwzwykgkuuu4m9yvqavxwn2g0c5gf87c67jdsqv9qu0p3kgvjz3z5jjeu2u5e4ghc2hg938rhzwlsnynte87gytvvv9t59nr53x97pfnj2dtgu2n08zqyhudegr7fm9jjm2vsm56pm3k9ha75hyveg57pl78mers9ykd5gp9d939z63ndvrqycenptqga8pqpdpqaze53y7t9y5p8hwrnwaavus5ef22wj07kaqzf409gxx2d3yk76t2rm2rnglxks6q3jrkncmpdm0vah5a8425659m93jz0y7lmka2nnyljdpr3rc7eq6s4v609rameuywylduk4l6s2fdyr34zmdu75yxhezhyxaj9g7cfqhzvjeyrp7ydrjtfas0k7rz2yky32c8p5kxhyc0xcs3zharxuz0ul3etn4sagmcu3gtr4szn9gsnz5esl0tywe4lgyagqc7ud8tzg0w5grq2geskccm0dckn2vfjmpzyqcnxggrnrux3t04vm7vtylnhu4c0gwuaff0t7m4ng8hr45eq";

#[test]
#[ignore]
fn generate_keys() -> Result<()> {
    let secret1 = SecretKey::new(
        multicodec_prefix::ED25519_SECRET,
        None,
        None,
        Some("secret"),
        Some("pub"),
    )?;
    println!("const SECRET1: &str = \"{secret1}\";");
    println!(
        "const PUBLIC1: &str = \"{}\";",
        PublicKey::try_from(secret1.public_key()).unwrap()
    );
    let secret2 = SecretKey::new(
        multicodec_prefix::P521_SECRET,
        None,
        None,
        Some("secret"),
        Some("pub"),
    )?;
    println!("const SECRET2: &str = \"{secret2}\";");
    println!(
        "const PUBLIC2: &str = \"{}\";",
        PublicKey::try_from(secret2.public_key()).unwrap()
    );
    let secret3 = SecretKey::new(
        multicodec_prefix::CUSTOM,
        Some("Falcon-512"),
        None,
        Some("secret"),
        Some("pub"),
    )?;
    println!("const SECRET3: &str = \"{secret3}\";");
    println!(
        "const PUBLIC3: &str = \"{}\";",
        PublicKey::try_from(secret3.public_key()).unwrap()
    );
    Ok(())
}

#[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
#[test]
fn it_can_serialize_and_deserialize1() {
    let secret_key = SecretKey::from_str(SECRET1).expect("cannot read string");
    let public_key = PublicKey::try_from(secret_key.public_key()).unwrap();

    assert_eq!(secret_key.to_string(), SECRET1);
    assert_eq!(public_key.to_string(), PUBLIC1);

    let public_key = PublicKey::from_str(PUBLIC1).expect("cannot read string");
    assert_eq!(public_key.to_string(), PUBLIC1);

    let secret_key: SecretKey = SecretKey::new(
        multicodec_prefix::ED25519_SECRET,
        None,
        None,
        Some("secret"),
        Some("pub"),
    )
    .expect("cannot create key");
    let public_key = PublicKey::try_from(secret_key.public_key()).unwrap();

    //println!("{secret_key} {public_key}");

    let secret_key_bytes = secret_key.to_bytes();
    let public_key_bytes = public_key.to_bytes();
    let secret_key_str = secret_key.to_string();
    let public_key_str = public_key.to_string();

    let restored_secret_key =
        SecretKey::try_from(secret_key_bytes.as_slice()).expect("cannot parse");
    assert_eq!(restored_secret_key.to_bytes(), secret_key_bytes);
    let restored_public_key = restored_secret_key.public_key();
    assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

    let restored_public_key =
        PublicKey::try_from(public_key_bytes.as_slice()).expect("cannot parse");
    assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

    let restored_secret_key = SecretKey::from_str(&secret_key_str).expect("cannot parse");
    assert_eq!(restored_secret_key.to_bytes(), secret_key_bytes);
    let restored_public_key = restored_secret_key.public_key();
    assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

    let restored_public_key = PublicKey::from_str(&public_key_str).expect("cannot parse");
    assert_eq!(restored_public_key.to_bytes(), public_key_bytes);
}

#[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
#[test]
fn it_can_serialize_and_deserialize2() -> Result<()> {
    let secret_key = SecretKey::from_str(SECRET2)?;
    let public_key = PublicKey::try_from(secret_key.public_key())?;

    assert_eq!(secret_key.to_string(), SECRET2);
    assert_eq!(public_key.to_string(), PUBLIC2);

    let public_key = PublicKey::from_str(PUBLIC2)?;
    assert_eq!(public_key.to_string(), PUBLIC2);

    let secret_key: SecretKey = SecretKey::new(
        multicodec_prefix::P521_SECRET,
        None,
        None,
        Some("secret"),
        Some("pub"),
    )?;
    let public_key = PublicKey::try_from(secret_key.public_key())?;

    //println!("{secret_key} {public_key}");

    let secret_key_bytes = secret_key.to_bytes();
    let public_key_bytes = public_key.to_bytes();
    let secret_key_str = secret_key.to_string();
    let public_key_str = public_key.to_string();

    let restored_secret_key = SecretKey::try_from(secret_key_bytes.as_slice())?;
    assert_eq!(restored_secret_key.to_bytes(), secret_key_bytes);
    let restored_public_key = restored_secret_key.public_key();
    assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

    let restored_public_key = PublicKey::try_from(public_key_bytes.as_slice())?;
    assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

    let restored_secret_key = SecretKey::from_str(&secret_key_str)?;
    assert_eq!(restored_secret_key.to_bytes(), secret_key_bytes);
    let restored_public_key = restored_secret_key.public_key();
    assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

    let restored_public_key = PublicKey::from_str(&public_key_str)?;
    assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

    Ok(())
}

#[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
#[test]
fn it_can_serialize_and_deserialize3() -> Result<()> {
    let secret_key = SecretKey::from_str(SECRET3)?;
    let public_key = PublicKey::try_from(secret_key.public_key())?;

    assert_eq!(secret_key.to_string(), SECRET3);
    assert_eq!(public_key.to_string(), PUBLIC3);

    let public_key = PublicKey::from_str(PUBLIC3)?;
    assert_eq!(public_key.to_string(), PUBLIC3);

    let secret_key: SecretKey = SecretKey::new(
        multicodec_prefix::CUSTOM,
        Some(known_algorithm_name::Falcon512),
        None,
        Some("secret"),
        Some("pub"),
    )?;
    let public_key = PublicKey::try_from(secret_key.public_key())?;

    //println!("{secret_key} {public_key}");

    let secret_key_bytes = secret_key.to_bytes();
    let public_key_bytes = public_key.to_bytes();
    let secret_key_str = secret_key.to_string();
    let public_key_str = public_key.to_string();

    let restored_secret_key = SecretKey::try_from(secret_key_bytes.as_slice())?;
    assert_eq!(restored_secret_key.to_bytes(), secret_key_bytes);
    let restored_public_key = restored_secret_key.public_key();
    assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

    let restored_public_key = PublicKey::try_from(public_key_bytes.as_slice())?;
    assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

    let restored_secret_key = SecretKey::from_str(&secret_key_str)?;
    assert_eq!(restored_secret_key.to_bytes(), secret_key_bytes);
    let restored_public_key = restored_secret_key.public_key();
    assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

    let restored_public_key = PublicKey::from_str(&public_key_str)?;
    assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

    Ok(())
}

#[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
#[test]
fn it_can_serialize_and_deserialize_json() {
    let secret_key = SecretKey::from_str(SECRET1).expect("cannot read string");
    let public_key = PublicKey::try_from(secret_key.public_key()).unwrap();

    let text = serde_json::to_string_pretty(&public_key).expect("cannot serialize");
    assert_eq!(text, format!("\"{PUBLIC1}\""));

    let public_key_1: PublicKey = serde_json::from_str(&text).expect("cannot deserialize");
    assert_eq!(public_key_1.to_bytes(), public_key.to_bytes());
}

#[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
#[test]
fn it_can_serialize_and_deserialize_binary() {
    let secret_key = SecretKey::from_str(SECRET1).expect("cannot read string");
    let public_key = PublicKey::try_from(secret_key.public_key()).unwrap();

    let bytes = serde_ipld_dagcbor::to_vec(&public_key).expect("cannot serialize");

    let public_key_1: PublicKey =
        serde_ipld_dagcbor::from_slice(&bytes).expect("cannot deserialize");
    assert_eq!(public_key_1.to_bytes(), public_key.to_bytes());
}

#[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
#[test]
fn public_key_is_consistent1() -> Result<()> {
    let secret_key = SecretKey::from_str(SECRET1)?;
    let public_key1 = PublicKey::try_from(secret_key.public_key())?;
    let public_key2 = PublicKey::try_from(secret_key.public_key())?;

    assert_eq!(public_key1.to_string(), PUBLIC1);
    assert_eq!(public_key1.to_string(), public_key2.to_string());
    Ok(())
}

#[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
#[test]
fn public_key_is_consistent2() -> Result<()> {
    let secret_key = SecretKey::from_str(SECRET2)?;
    let public_key1 = PublicKey::try_from(secret_key.public_key())?;
    let public_key2 = PublicKey::try_from(secret_key.public_key())?;

    assert_eq!(public_key1.to_string(), PUBLIC2);
    assert_eq!(public_key1.to_string(), public_key2.to_string());
    Ok(())
}

#[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
#[test]
fn public_key_is_consistent3() -> Result<()> {
    let secret_key = SecretKey::from_str(SECRET3)?;
    let public_key1 = PublicKey::try_from(secret_key.public_key())?;
    let public_key2 = PublicKey::try_from(secret_key.public_key())?;

    assert_eq!(public_key1.to_string(), PUBLIC3);
    assert_eq!(public_key1.to_string(), public_key2.to_string());
    Ok(())
}

#[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
#[test]
fn it_can_sign_and_verify_a_message1() -> Result<()> {
    let secret_key = SecretKey::from_str(SECRET1)?;
    let public_key = secret_key.public_key();
    let data = b"test data";
    let nonce = b"12345678";
    let mut attrs = SignatureAttributes::default();
    attrs.set_nonce(Some(nonce));
    let signature = secret_key.sign_deterministic(data, None, Some(&mut attrs))?;

    assert_eq!(
        signature.to_string(),
        "zgJegREETcdWVaKfaKgtjjrVfC7fC2wVMBpg9Wvhfuo1JgKWsoFKe6n99F4Zq6DZffuAeNE3vwZzFj2LXt7fUmnJ8EunaHAPmbeJi2P2SeZefwEc7"
    );
    secret_key.verify(data, &signature)?;
    public_key.verify(data, &signature)?;

    Ok(())
}

#[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
#[test]
fn it_can_sign_and_verify_a_message2() -> Result<()> {
    let secret_key = SecretKey::from_str(SECRET2)?;
    let public_key = secret_key.public_key();
    let data = b"test data";
    let nonce = b"12345678";
    let mut attrs = SignatureAttributes::default();
    attrs.set_nonce(Some(nonce));
    let signature = secret_key.sign_deterministic(data, None, Some(&mut attrs))?;

    // P521 signature contains random
    // assert_eq!(signature.to_string(), "BTCCuYnLBQKhMzbKhDHMFgMwwDHmyjyvtBwobyXthvgUFYAQN9yqfbrbM3ZMshQpHJL7u5LK2B9BPB6jfYB1qXaDd8J83ryzF5PQAkE8CRmMd2jxJnphH9BWkYpCoNopi5d5X2dAmrgTSY12REcxhrkUPMF25J8vsV3P2wdTgHr3nGB8CLYn3SnBQYBRe2BXkX7ftg96y5MvvWMBm");
    secret_key.verify(data, &signature)?;
    public_key.verify(data, &signature)?;

    Ok(())
}

#[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
#[test]
fn it_can_sign_and_verify_a_message3() -> Result<()> {
    let secret_key = SecretKey::from_str(SECRET3)?;
    let public_key = secret_key.public_key();
    let data = b"test data";
    let nonce = b"12345678";
    let mut attrs = SignatureAttributes::default();
    attrs.set_nonce(Some(nonce));
    let signature = secret_key.sign_deterministic(data, None, Some(&mut attrs))?;

    // assert_eq!(signature.to_string(), "BTCCuYnLBQKhMzbKhDHMFgMwwDHmyjyvtBwobyXthvgUFYAQN9yqfbrbM3ZMshQpHJL7u5LK2B9BPB6jfYB1qXaDd8J83ryzF5PQAkE8CRmMd2jxJnphH9BWkYpCoNopi5d5X2dAmrgTSY12REcxhrkUPMF25J8vsV3P2wdTgHr3nGB8CLYn3SnBQYBRe2BXkX7ftg96y5MvvWMBm");
    secret_key.verify(data, &signature)?;
    public_key.verify(data, &signature)?;

    Ok(())
}

#[cfg_attr(all(target_family = "wasm", target_os = "unknown"), wasm_bindgen_test)]
#[test]
fn test_encode_decode_did() -> Result<()> {
    let secret_key = SecretKey::from_str(SECRET1)?;
    let public_key = PublicKey::try_from(secret_key.public_key()).unwrap();

    let did1 = secret_key.get_did()?;
    let did2 = public_key.get_did()?;

    assert_eq!(
        did1.to_string(),
        "did:key:pub_xahgjw6qgrwp6kyqgpyzqnvfy45r2uwct508t4lfxfnp6uve2zgw7p8mtyan0dnlyra6k36vrqq7e5q90t6v"
    );
    assert_eq!(did1, did2);

    let public_key2 = PublicKey::try_from(&did1)?;
    assert_eq!(public_key2.to_string(), PUBLIC1);
    assert_eq!(public_key2.to_string(), PUBLIC1);
    assert_eq!(public_key2.to_string(), public_key.to_string());
    //assert_eq!(public_key2, public_key);

    Ok(())
}
