fn main() {
    let ciphertexts = vec![
        "160111433b00035f536110435a380402561240555c526e1c0e431300091e4f04451d1d490d1c49010d000a0a4510111100000d434202081f0755034f13031600030d0204040e",
        "050602061d07035f4e3553501400004c1e4f1f01451359540c5804110c1c47560a1415491b06454f0e45040816431b144f0f4900450d1501094c1b16550f0b4e151e03031b450b4e020c1a124f020a0a4d09071f16003a0e5011114501494e16551049021011114c291236520108541801174b03411e1d124554284e141a0a1804045241190d543c00075453020a044e134f540a174f1d080444084e01491a090b0a1b4103570740",
        "000000000000001a49320017071704185941034504524b1b1d40500a0352441f021b0708034e4d0008451c40450101064f071d1000100201015003061b0b444c00020b1a16470a4e051a4e114f1f410e08040554154f064f410c1c00180c0010000b0f5216060605165515520e09560e00064514411304094c1d0c411507001a1b45064f570b11480d001d4c134f060047541b185c",
        "0b07540c1d0d0b4800354f501d131309594150010011481a1b5f11090c0845124516121d0e0c411c030c45150a16541c0a0b0d43540c411b0956124f0609075513051816590026004c061c014502410d024506150545541c450110521a111758001d0607450d11091d00121d4f0541190b45491e02171a0d49020a534f",
        "031a5410000a075f5438001210110a011c5350080a0048540e431445081d521345111c041f0245174a0006040002001b01094914490f0d53014e570214021d00160d151c57420a0d03040b4550020e1e1f001d071a56110359420041000c0b06000507164506151f104514521b02000b0145411e05521c1852100a52411a0054180a1e49140c54071d5511560201491b0944111a011b14090c0e41",
        "0b4916060808001a542e0002101309050345500b00050d04005e030c071b4c1f111b161a4f01500a08490b0b451604520d0b1d1445060f531c48124f1305014c051f4c001100262d38490f0b4450061800004e001b451b1d594e45411d014e004801491b0b0602050d41041e0a4d53000d0c411c41111c184e130a0015014f03000c1148571d1c011c55034f12030d4e0b45150c5c",
        "011b0d131b060d4f5233451e161b001f59411c090a0548104f431f0b48115505111d17000e02000a1e430d0d0b04115e4f190017480c14074855040a071f4448001a050110001b014c1a07024e5014094d0a1c541052110e54074541100601014e101a5c",
        "0c06004316061b48002a4509065e45221654501c0a075f540c42190b165c",
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    ];
    let ciphertexts: Vec<Vec<u8>> = ciphertexts
        .iter()
        .map(|s| hex::decode(s).unwrap())
        .collect();

    let mut cleartexts: Vec<Vec<u8>> = ciphertexts
        .iter()
        .map(|line| vec![b'?' ; line.len()])
        .collect();

    let key = "Bitcoin: A purely peer-to-peer version of electronic cash would allow online payments to be sent directly from one party to another without going through a financial institution.";
    
    println!("\n\n////////////////////Cracking the CipherTexts//////////////////");
    crack(&ciphertexts, &mut cleartexts, false);
    println!("\n\n////////////////////Decrypting the CipherTexts////////////////");
    decrypt(&ciphertexts, &mut cleartexts, key);

    let ciphertext = "cbe0fdeae6e0e7b3a9c8a9f9fcfbece5f0a9f9ecec526e1b014a020411074c17111b1c071c4e4f0146430d0d08131d1d010707040017091648461e1d0618444f074c010e19594f0f1f1a07024e1d041719164e1c1652114f411645541b004e244f080213010c004c3b4c0911040e480e070b00310213101c4d0d4e00360b4f151a005253184913040e115454084f010f114554111d1a550f0d52040146e0e7e8e7eae0e8e5a9e0e7fafde0fdfcfde0e6e7a7";
    let decoded_string = decode_final_cyphertext_with_key(&ciphertext, key);
    println!("\n\nDecoded Final String: {:?}", decoded_string);
}

fn decode_final_cyphertext_with_key(ciphertext: &str, key: &str) -> String {
    let ciphertext_bytes = hex::decode(ciphertext).expect("Decoding failed");
    let key_bytes = key.as_bytes();
    let mut decoded_bytes = Vec::new();

    for (i, &cipher_byte) in ciphertext_bytes.iter().enumerate() {
        let decoded_byte = cipher_byte ^ key_bytes[i % key_bytes.len()];
        decoded_bytes.push(decoded_byte);
    }

    String::from_utf8_lossy(decoded_bytes.as_slice()).to_string()
}

fn decrypt(ciphertexts: &Vec<Vec<u8>>, cleartexts: &mut Vec<Vec<u8>>, input_key: &str) {
    let key = input_key.as_bytes();
    for (row, ciphertext) in ciphertexts.iter().enumerate() {
        for (column, &cipher) in ciphertext.iter().enumerate() {
            cleartexts[row][column] = cipher ^ key[column % key.len()];
        }
        println!("{}", String::from_utf8(cleartexts[row].clone()).unwrap());
    }
}

fn crack(ciphertexts: &Vec<Vec<u8>>, cleartexts: &mut Vec<Vec<u8>>, getkey: bool) {
    let max_length = ciphertexts.iter().map(|line| line.len()).max().unwrap();
    let mut key = vec![0u8; max_length];
    let mut key_mask = vec![false; max_length];

    for column in 0..max_length {
        let pending_ciphers: Vec<&Vec<u8>> = ciphertexts.iter().filter(|line| line.len() > column).collect();
        for cipher in &pending_ciphers {
            if is_space(&pending_ciphers, cipher[column], column) {
                key[column] = cipher[column] ^ b' ';
                key_mask[column] = true;
                let mut i = 0;
                for clear_row in 0..cleartexts.len() {
                    if !cleartexts[clear_row].is_empty() && column < cleartexts[clear_row].len() {
                        let result = cipher[column] ^ pending_ciphers[i][column];
                        if result == 0 {
                            cleartexts[clear_row][column] = b' ';
                        } else if (result as char).is_uppercase() {
                            cleartexts[clear_row][column] = (result as char).to_lowercase().next().unwrap() as u8;
                        } else if (result as char).is_lowercase() {
                            cleartexts[clear_row][column] = (result as char).to_uppercase().next().unwrap() as u8;
                        }
                        i += 1;
                    }
                }
                break;
            }
        }
    }

    if getkey {
        for pos in 0..max_length {
            if key_mask[pos] {
                print!("{:02x}", key[pos]);
            } else {
                print!("__");
            }
        }
        println!();
    } else {
        for line in cleartexts {
            println!("{}", String::from_utf8(line.clone()).unwrap());
        }
    }
}

fn is_space(rows: &Vec<&Vec<u8>>, current: u8, column: usize) -> bool {
    for row in rows {
        let result = row[column] ^ current;
        if !(is_alpha(result) || result == 0) {
            return false;
        }
    }
    true
}

fn is_alpha(c: u8) -> bool {
    (c >= b'a' && c <= b'z') || (c >= b'A' && c <= b'Z')
}