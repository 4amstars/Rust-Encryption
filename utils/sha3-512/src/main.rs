
#![windows_subsystem = "windows"]

use native_windows_gui as nwg;
use sha3::{Digest, Sha3_512};
use std::cell::RefCell;
use std::rc::Rc;

#[derive(Default)]
pub struct NwgUi {
    window: nwg::Window,
    input: nwg::TextInput,
    input_label: nwg::Label,
    generate_button: nwg::Button,
    clear_button: nwg::Button,
    output_label: nwg::Label,
    output: nwg::TextBox,
}

fn main() {
    // Initialize NWG and set a global font family
    nwg::init().expect("Failed to initialize GUI");
    nwg::Font::set_global_family("Segoe UI").expect("Failed to set default font");

    // Create UI structure
    let mut ui = NwgUi::default();

    // Build window
    nwg::Window::builder()
        .size((1000, 600))
        .position((300, 300))
        .title("SHA3-512 Hash Generator")
        .build(&mut ui.window)
        .expect("Failed to create main window");

    // Input label
    nwg::Label::builder()
        .text("Input Text:")
        .size((980, 20))
        .position((10, 10))
        .parent(&ui.window)
        .build(&mut ui.input_label)
        .expect("Failed to create input label");

    // Input text box
    nwg::TextInput::builder()
        .size((980, 25))
        .position((10, 30))
        .parent(&ui.window)
        .build(&mut ui.input)
        .expect("Failed to create input box");

    // Generate hash button
    nwg::Button::builder()
        .size((480, 30))
        .position((10, 65))
        .text("Generate Hash")
        .parent(&ui.window)
        .build(&mut ui.generate_button)
        .expect("Failed to create 'Generate Hash' button");

    // Clear button
    nwg::Button::builder()
        .size((480, 30))
        .position((510, 65))
        .text("Clear")
        .parent(&ui.window)
        .build(&mut ui.clear_button)
        .expect("Failed to create 'Clear' button");

    // Output label
    nwg::Label::builder()
        .text("Hash Output:")
        .size((980, 20))
        .position((10, 105))
        .parent(&ui.window)
        .build(&mut ui.output_label)
        .expect("Failed to create output label");

    // Font for the output textbox
    let mut output_font = nwg::Font::default();
    nwg::Font::builder()
        .size(12)
        .family("Consolas")
        .build(&mut output_font)
        .expect("Failed to create output font");

    // Output textbox
    nwg::TextBox::builder()
        .size((980, 450))
        .position((10, 130))
        .text("")
        .parent(&ui.window)
        .readonly(true)
        .font(Some(&output_font))
        .build(&mut ui.output)
        .expect("Failed to create output box");

    // Shareable reference to the UI state
    let ui_ref = Rc::new(RefCell::new(ui));
    let ui_handler = Rc::clone(&ui_ref);

    // Event handler for button clicks and window close
    let handler = move |evt, _evt_data, handle| {
        let ui = ui_handler.borrow_mut();  // Removed 'mut' since ui doesn't need to be mutable
        match evt {
            nwg::Event::OnButtonClick => {
                if handle == ui.generate_button {
                    // Get input text and validate
                    let input_text = nwg::TextInput::text(&ui.input).trim().to_string();
                    if input_text.is_empty() {
                        ui.output.set_text("Error: Input is empty. Please enter text to hash.");
                        return;
                    }

                    // Generate the SHA3-512 hash
                    let mut hasher = Sha3_512::new();
                    hasher.update(input_text.as_bytes());
                    let result = hasher.finalize();
                    let hash_str = format!("{:x}", result);

                    // Append hash to output box
                    let current_text = ui.output.text();
                    let new_text = if current_text.is_empty() {
                        hash_str
                    } else {
                        format!("{}\r\n{}", current_text, hash_str)
                    };
                    ui.output.set_text(&new_text);
                } else if handle == ui.clear_button {
                    // Clear the output box
                    ui.output.set_text("");
                }
            }
            nwg::Event::OnWindowClose => {
                if handle == ui.window {
                    nwg::stop_thread_dispatch();
                }
            }
            _ => {}
        }
    };

    // Bind event handler to the window
    nwg::full_bind_event_handler(&ui_ref.borrow().window.handle, handler);
    
    // Start event loop
    nwg::dispatch_thread_events();
}
