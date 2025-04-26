use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::Read;

pub fn sha256_checksum(path: &str) -> Result<String, String> {
    let mut file = File::open(path).map_err(|e| e.to_string())?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let read = file.read(&mut buf).map_err(|e| e.to_string())?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }
    let hash = hasher.finalize();
    Ok(format!("{:x}", hash))
}

pub fn analyze_entropy(file_path: &str, report_path: &str) -> Result<(), String> {
    let mut file = File::open(file_path).map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).map_err(|e| e.to_string())?;

    let mut counts = [0u64; 256];
    for &b in &buf {
        counts[b as usize] += 1;
    }

    let total = buf.len() as f64;
    let entropy = counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / total;
            -p * p.log2()
        })
        .sum::<f64>();

    let (min_byte, min_count) = counts
        .iter()
        .enumerate()
        .min_by_key(|(_, &count)| count)
        .unwrap();
    let (max_byte, max_count) = counts
        .iter()
        .enumerate()
        .max_by_key(|(_, &count)| count)
        .unwrap();

    let mut has_repeat = false;
    for window in buf.windows(16) {
        if window.windows(4).any(|chunk| chunk.iter().all(|&b| b == window[0])) {
            has_repeat = true;
            break;
        }
    }

    let mut html = String::new();
    html.push_str("<!DOCTYPE html><html><head><meta charset=\"UTF-8\">");
    html.push_str("<style>body{font-family:monospace;padding:2em;background:#f7f7f7;} table{border-collapse:collapse;width:100%;}th,td{border:1px solid #ccc;padding:5px;text-align:left;}th{background:#eee;}</style>");
    html.push_str("<title>Entropy Report</title></head><body>");
    html.push_str("<h1>Entropy Report</h1>");
    html.push_str(&format!("<p><strong>File:</strong> {}</p>", file_path));
    html.push_str(&format!("<p><strong>Size:</strong> {} bytes</p>", total));
    html.push_str(&format!("<p><strong>Entropy:</strong> {:.6} bits/byte</p>", entropy));
    html.push_str(&format!(
        "<p><strong>Most frequent byte:</strong> 0x{:02X} ({} times)</p>",
        max_byte, max_count
    ));
    html.push_str(&format!(
        "<p><strong>Least frequent byte:</strong> 0x{:02X} ({} times)</p>",
        min_byte, min_count
    ));
    html.push_str(&format!(
        "<p><strong>Repeating 4-byte pattern detected:</strong> {}</p>",
        if has_repeat { "Yes ❌" } else { "No ✅" }
    ));

    html.push_str("<h2>Byte Frequency</h2><table><tr><th>Byte</th><th>Count</th></tr>");
    for (i, &c) in counts.iter().enumerate() {
        html.push_str(&format!(
            "<tr><td>0x{:02X}</td><td>{}</td></tr>",
            i, c
        ));
    }
    html.push_str("</table></body></html>");

    fs::write(report_path, html).map_err(|e| e.to_string())?;

    Ok(())
}
