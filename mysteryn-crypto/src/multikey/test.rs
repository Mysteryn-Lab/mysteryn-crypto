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

const SECRET1: &str = "secret_xahgjgqfsxwdjkxun9wspqzgy85w6a709xu0qk3hl0unyc7ytc8dmgca22w4ejswdjkgdde6d4r58qxur4v2xmyflkjl4eg";
const PUBLIC1: &str =
    "pub_xahgjw6qgrwp6kyqgpyr9pgcew6cmv6qpncr8gd2a2r79mgz37ee0x056u94lx8hnhzgue56gqzvavws4r";
const SECRET2: &str = "secret_xahgjgsfsxwdjkxun9wspqzsspak7s48tzxwajmtvdlfkvgux7sefls9xq2k3qlm8502v796aaqmt5hqypusekcfhz4fwwmx6tyl5e8e3xv35cw0xdwpc242hvd465hwzfpcphqatzyssp4gegs5qs";
const PUBLIC2: &str = "pub_xahgjgyfqrwp6kyqgpgvpspxer6cp8tq30ste0np6ux0xpkrjrwucgyr0md6nrsty8caez453eu2v5jx9ud8pddged37n7v38wdfq04lxxwgu63g46gxakyj6fuzqcuv3sqazaz8xj";
const SECRET3: &str = "secret_xahgjqqpnnv43hyet5qsqczzjezsh58ep0c8elqsgrkrr7qg9ml0c5r7qlscvqqllsqrp00u97a3qr7zql80sqzswn3ap0ggvzywhmamq00vy97sg07zqsq4qzal8cqql0qqfur7s86pz3chl7zq0uyp7q05fllqsralrl00aau3crmcp0qnuzzlcremq3gr6p7p85967qc5n7zqg5vpl0gqgrz0c8uxp0qg9a70hl3aq0e87palsyzruss8llujhvvprplufma3hcfkusggxpr0pq8cplgytlq0sreu7qh86p7lcyhaywllh7lllvgqqsscxp7s3huyppguw97werem73gyxq7lhudmu0hy8uzqqhvyalssparlc8aml0gmnmp7gy96pssm7qqqqyxzz0ct7qqslhhapq8m6ql0q5r77qlv9u6l0ll777lmkxal85zqp3q8al77cn7xpqgv2x9qgy2r7qhn59rpgluzu0qc9llpsmjzllluwpa705r6zlcr7rlwgyypzapq87z3q0aerqg0a6lwlvp6plcnma7lkrha77cs9lq0luf7assvrapsgtl7rlgn5zp0qspelsgyzyl0hm4uzqsyplqlegjpp38hl7q0lvqxpp8gxzq38cplpscqzzljqyqp7wcncplsghczq0hqzyz38sqplas8cprphufalqsszqzpggyrlslszxpwlh7xa0crcp7sqsg9lsf0477sq079y7cvr7q7llcryssq9azp0vxqqls8elqs80m7p3qyzzps08kt7lsugrpl0huyzqc8auaw8sq9l0sr5ppqcrnaljsukr7ssgt7pqx59a7ssyr7uq8mhlrzfy8ezsqth66lllczlqx5xy7s8nvxlqcvgzq0c8jz7lh5gpllcy9lpwg0maq7hvvzpwcnaeqlhu9eqllluplq8muzlsgsyppp0tkq7qqs96l3g0kq77llll70sqzqq3gtupp30ctcpqsr7rpq0tcyzwg8uq7qhhc970ct3aq3hurlpqcsr7psq0czqq8vt6lsqgqxlpq86zz3cruzl3srcrzlsn5xzqe8kralgn3ulqlv47u0sr4lp30h6qpl0upa7psvgplss06rz0qmdlzsq5gqaqg5tlap85qzllggxy70hc96qqsgq8yslhuzu0lm79zqqqxp7qs0u9plqvgzq3gnm6ll8tkglss07zz3052xqsgypmrs8nea70lnlmr0gsdap0g069zpcqqphsus5wsr33l5rss0chpvp7amxu7rnqdhgkucgah6hlqmn3nhkaq52a690uxygdleg6ph6q3ml3lgll7q8qyyxw59q8mmew5qg8r58lxxq7lv8a7x0f9xap58gd9m6zn5khpt9paee3m06w87lg7c8apcsdpl70jxfl9yy7n076y0nlpeheygx0pehsam27w98qumg3p40k60azpc3zavdq7zsuu053e6enlytsr6pslq5qtae3u8075qe0py43vyhx7lc7eagd8vzrf60was9ltcguus9s6d0qp85p5rstlhflqqsyrg9qkx0gltaqraqjlnk3ak8dznt3d68lrt7zqg8v7r3q4cscq87axpcea09skqh6lc870m0sy5yluv8suq07wqg8rqrrgwqs7n3qph04ryfz0l0n7mnnr6lmrrnqyqhk9rm3c90vlr9jgyp3znndwz866nxl0cgxumm0cpp7quganmdl98a3wysv9vmz6nlmly8phl0uzgnqw4eyqsgq8ehsm59p8lhlpme378gqztaqpm8mlt532rqzpv8dmke6zyq0hm0jqqj7a57eqq5w438kq80skrg37g2llkqhac5drlqzur5v4nhczmlpkrgrulcu5dk4zrm02zlymlcl7zh9pvplwx0eulhq7ql6qqfjp7lh7m0wxystzt4sn5llzu2qdccxlqd0d40gpyjpxzfrqu27gqclmurq5pqs6u806pqwhm7avpde7h6skssdahp7pugqxh77u9ftlugwlcq9augqm4g2a0msdlcwlvfl4esqm86su8cqqhhq8mhpps9yvctvvdhkutf4xyeq6qgppcphqatz2yv8amvs6hpqwjznchpchqyy2wmkgg93zwrnuu47jszvqyuveyjaecd483yz5xp0tkcanz8l9sw4zknu8yn5kmcsaan8anqcq0kgmlyrrkvv0vzf2qhxzwpw9w4s";
const PUBLIC3: &str = "pub_xahgjqqqmsw43qyqvpquyetxgpukreclfump0w2tclg30j5np6kfnj2wrz882ce54zv37tppt5edlz2705j7e3g3pmdjhwk7r24kvuugvjlp2s6xuggqygv86qvzag8krkrwxt73gyqkkgfe9geedpjm3gf77xnz93uhkaqwp7k4p9aexhzf2e8e05g0wr9mztgw2ume4sf58nkx7mgwxg9rvx5g9wk8rcsmaz7nyqvazjy328eu2zaaxvef2acpfz6f73rrxhrd3w3math2h7w7yxx4u9z3nztfvgfc9w4czgrkye3t93wscuxtt4p4ceuqhschw8aq0wcyqzl0s3upa3z5lq499yyknx9mfnvggdwe6p96rpz6xd7kwdal8clqs7e2j25xmqqxl2257rszv8zhskqzpk5geum4t79qae54kaxqx93tdt4fjx0tlpz72r0fsyp8krc652eda2gwz8y89ufcmynek5kqttverces8my62c0dr9ps5jpf53wrwrrakruf3qv85n2wdklytk39u6nhpql3uc3lj8f0y4zl5a35g5wh6xh223k6u5vwl2r2yycj7gl6sc75ef04z94wu8yzrcjk4y8w0e5lm2jncmx550p5pd4mwscmj3t8mj4c9kmpndxjkkdssra95h7xrxxw5y4en7m477j0vszqer9k29lsdq20nw69u4w6hqfdsvx48h40060drmcfrp3kyal9g9j4yxng8fvqqp4ppxzqjq48jgmz76jjs03xqw6qxxadt3fyp9urmy6ej9486vpdufr8xj50tcu8yj6fd6mn0xysqfrcm9ygmxdxx6tyzsmescxyn5h5nzss835q9edfwsezcf0z2am5d7xwmx2yad5sghvn3a6h92c99aj4ds2d6ffq4uzkp8unp2h9nvtkfxrfmuqn7news7ug78s28pydp4j94vnz0z2r9zlkj2akkrm6jlju8796ny2mheqg7r66jgz2d23pjryhtxr8j4seeufaky4alasdmnme2nx9nu94fzppwhd4usjdl5rvfgtexz5ww2sl6p7q5pjquyj5569jsg6v32q9js3gr0y99vp58xuvq93nzxlvhk76577uptckhh29pd6zhv5ezhrzqzqzrqkxn88f75vqz5pd6ffy6qsvnkhzckvyfxtkyk24vvnjyhsw3xr9gjs3hyx8vvczudrmv6pzkwfvwfym439ta92e4zygcn304t33e6yelqp6nrtfrxxrvrv6wfvaqnf5pfvsw69sg5ugkfa8clj49zxewpzq9353k8tsnvlq0us4dmpzeg2666r6zefj7xmns87tqd0xuw9g67plj70ul65tle7xzyu9a429z2p2rv82cejfu09r5grqjg528yk8d34e0twl8twdksps6yns2ndv27sfyr7twsru2l46uhv64n3z08wrq2geskccm0dckn2vfjksnpmyhupytmn746cp9r468xus3njaw7ag8tuefpj99mj4amy74nnzcqhsn55fcvwmeh6uu88p2f346z6zja8lwejv";

// Generate the above keys.
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

    let restored_secret_key = SecretKey::try_from(secret_key_bytes.as_ref()).expect("cannot parse");
    assert_eq!(restored_secret_key.to_bytes(), secret_key_bytes);
    let restored_public_key = restored_secret_key.public_key();
    assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

    let restored_public_key = PublicKey::try_from(public_key_bytes.as_ref()).expect("cannot parse");
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

    let restored_secret_key = SecretKey::try_from(secret_key_bytes.as_ref())?;
    assert_eq!(restored_secret_key.to_bytes(), secret_key_bytes);
    let restored_public_key = restored_secret_key.public_key();
    assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

    let restored_public_key = PublicKey::try_from(public_key_bytes.as_ref())?;
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

    let restored_secret_key = SecretKey::try_from(secret_key_bytes.as_ref())?;
    assert_eq!(restored_secret_key.to_bytes(), secret_key_bytes);
    let restored_public_key = restored_secret_key.public_key();
    assert_eq!(restored_public_key.to_bytes(), public_key_bytes);

    let restored_public_key = PublicKey::try_from(public_key_bytes.as_ref())?;
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
        "zgJegREETcdXVk8QkQ573P7ZuN7Cp4MFcXgR7FHjFWL75SECGq74beg58yYWnhuCkxVCjtuvs21sfPiCQnWPsvBG6yVZngBC53X2egA4yCcrwviz3"
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
        "did:key:pub_xahgjw6qgrwp6kyqgpyr9pgcew6cmv6qpncr8gd2a2r79mgz37ee0x056u94lx8hnhzgue56gqzvavws4r"
    );
    assert_eq!(did1, did2);

    let public_key2 = PublicKey::try_from(&did1)?;
    assert_eq!(public_key2.to_string(), PUBLIC1);
    assert_eq!(public_key2.to_string(), PUBLIC1);
    assert_eq!(public_key2.to_string(), public_key.to_string());
    //assert_eq!(public_key2, public_key);

    Ok(())
}
