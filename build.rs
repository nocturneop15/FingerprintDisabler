//! Generates the tray / exe icons procedurally and embeds them together with
//! a common-controls v6 manifest (activated at runtime by the tray UI).

use std::{env, fs, path::PathBuf};

const SIZES: [u32; 5] = [16, 20, 24, 32, 48];

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=res/app.manifest");

    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    let variants: [(&str, [u8; 3], bool); 3] = [
        ("normal", [0x2F, 0x80, 0xED], false), // watching, devices enabled
        ("active", [0xE5, 0x48, 0x4D], true),  // devices disabled (lid closed)
        ("paused", [0x8A, 0x8A, 0x8A], false), // paused / service not running
    ];

    let mut rc = String::new();
    for (i, (name, color, slash)) in variants.iter().enumerate() {
        let path = out.join(format!("{name}.ico"));
        fs::write(&path, make_ico(*color, *slash)).unwrap();
        rc.push_str(&format!("{} ICON \"{}\"\n", i + 1, fwd(&path)));
    }
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("res/app.manifest");
    // Resource ID 2 (not 1): Rust's std already embeds a default manifest as ID 1.
    // This one is activated at runtime by the tray UI (common controls v6).
    rc.push_str(&format!("2 24 \"{}\"\n", fwd(&manifest)));

    let rc_path = out.join("app.rc");
    fs::write(&rc_path, rc).unwrap();
    embed_resource::compile(&rc_path, embed_resource::NONE)
        .manifest_optional()
        .unwrap();
}

fn fwd(p: &std::path::Path) -> String {
    p.display().to_string().replace('\\', "/")
}

/// Renders a stylised fingerprint (concentric arcs) with optional slash.
fn render(size: u32, color: [u8; 3], slash: bool) -> Vec<u8> {
    let ss = 4u32; // supersampling
    let rings = if size <= 20 { 3 } else { 4 };
    let spacing = 0.43 / rings as f32;
    let thick = spacing * 0.52;
    let (cx, cy) = (0.5f32, 0.54f32);
    let mut px = vec![0u8; (size * size * 4) as usize];

    for y in 0..size {
        for x in 0..size {
            let mut cov = 0u32;
            for sy in 0..ss {
                for sx in 0..ss {
                    let fx = (x as f32 + (sx as f32 + 0.5) / ss as f32) / size as f32;
                    let fy = (y as f32 + (sy as f32 + 0.5) / ss as f32) / size as f32;
                    let (dx, dy) = (fx - cx, fy - cy);
                    let r = (dx * dx + dy * dy).sqrt();
                    // angle measured from "straight down"
                    let ang = dx.atan2(dy).abs();
                    let mut hit = r < thick * 0.6;
                    for k in 1..=rings {
                        let rk = k as f32 * spacing;
                        if (r - rk).abs() < thick / 2.0 {
                            // open the arcs at the bottom, outer ones more
                            let gap = 0.25 + 0.18 * k as f32;
                            if ang > gap {
                                hit = true;
                            }
                        }
                    }
                    if slash {
                        // distance to the diagonal line (top-left -> bottom-right)
                        let d = ((fx - fy) / std::f32::consts::SQRT_2).abs();
                        let on_seg = fx > 0.08 && fx < 0.92;
                        if on_seg && d < 0.075 {
                            hit = d < 0.045;
                        }
                    }
                    if hit {
                        cov += 1;
                    }
                }
            }
            let a = (cov * 255 / (ss * ss)) as u8;
            let i = ((y * size + x) * 4) as usize;
            px[i..i + 4].copy_from_slice(&[color[0], color[1], color[2], a]);
        }
    }
    px
}

fn make_ico(color: [u8; 3], slash: bool) -> Vec<u8> {
    let mut images = Vec::new();
    for &s in &SIZES {
        let rgba = render(s, color, slash);
        let mut bmp = Vec::new();
        let mask_row = s.div_ceil(32) * 4;
        // BITMAPINFOHEADER
        bmp.extend_from_slice(&40u32.to_le_bytes());
        bmp.extend_from_slice(&(s as i32).to_le_bytes());
        bmp.extend_from_slice(&((s * 2) as i32).to_le_bytes());
        bmp.extend_from_slice(&1u16.to_le_bytes());
        bmp.extend_from_slice(&32u16.to_le_bytes());
        bmp.extend_from_slice(&0u32.to_le_bytes());
        bmp.extend_from_slice(&(s * s * 4 + mask_row * s).to_le_bytes());
        bmp.extend_from_slice(&[0u8; 16]);
        for y in (0..s).rev() {
            for x in 0..s {
                let i = ((y * s + x) * 4) as usize;
                bmp.extend_from_slice(&[rgba[i + 2], rgba[i + 1], rgba[i], rgba[i + 3]]);
            }
        }
        bmp.extend(std::iter::repeat_n(0u8, (mask_row * s) as usize));
        images.push((s, bmp));
    }

    let mut ico = Vec::new();
    ico.extend_from_slice(&[0, 0, 1, 0]);
    ico.extend_from_slice(&(images.len() as u16).to_le_bytes());
    let mut offset = 6 + 16 * images.len() as u32;
    for (s, bmp) in &images {
        ico.push(if *s >= 256 { 0 } else { *s as u8 });
        ico.push(if *s >= 256 { 0 } else { *s as u8 });
        ico.extend_from_slice(&[0, 0]);
        ico.extend_from_slice(&1u16.to_le_bytes());
        ico.extend_from_slice(&32u16.to_le_bytes());
        ico.extend_from_slice(&(bmp.len() as u32).to_le_bytes());
        ico.extend_from_slice(&offset.to_le_bytes());
        offset += bmp.len() as u32;
    }
    for (_, bmp) in images {
        ico.extend_from_slice(&bmp);
    }
    ico
}
