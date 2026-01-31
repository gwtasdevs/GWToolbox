use pelite::pe32::{Pe, PeFile};
use std::{fs, io::Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
  let path = "gwca.dll";

  let mut data = fs::read(path)?;
  let pe = PeFile::from_bytes(&data)?;
  let exports = pe.exports()?;

  let exports = exports.by()?;
  let names = exports.names();
  for i in 0..names.len() {
    if let Ok(name) = pe.derva_c_str(names[i]) && name.to_string().contains("GetIsAgentTargettable") {
      let index = exports.name_indices()[i];
      let rva = exports.functions()[index as usize];
      let file_offset = pe.rva_to_file_offset(rva).expect("RVA not mapped");

      let scan_code: [u8; _] = [0xf7, 0x40, 0x10, 0x00, 0x00, 0x01, 0x00, 0x74, 0x13];

      for i in file_offset..file_offset+1000 {
        let bytes = &data[i..i+9];
        if bytes == scan_code {
          data[i+7] = 0xEB; // change JZ to JMP

          let mut file = fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(path)?;
          file.write_all(&data)?;
          return Ok(())
        }
      }

      return Err("Could not find the place to modify in the GetIsAgentTargettable function".into());
    }
  }

  Err("Could not find exported function GetIsAgentTargettable".into())
}
