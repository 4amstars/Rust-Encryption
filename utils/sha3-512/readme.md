











# SHA3-512 Hash Generator

This is a simple windows GUI application built with Rust that allows you to generate SHA3-512 hashes from any input text. The application uses the `native-windows-gui` crate for the graphical interface and the `sha3` crate for hash generation.

## Features

- **Generate SHA3-512 Hash:** Enter any text into the input box and click "Generate Hash" to compute the SHA3-512 hash of the input.
- **Clear Output:** Clear the generated hash output by clicking the "Clear" button.
- **GUI Application:** A graphical interface with text input, buttons, and a read-only text box to display the hash.

## Dependencies

The application requires the following Rust crates:

- [native-windows-gui](https://crates.io/crates/native-windows-gui) (v1.0.13): For creating the Windows GUI.
- [sha3](https://crates.io/crates/sha3) (v0.10.8): For generating SHA3-512 hashes.
- [winapi](https://crates.io/crates/winapi) (v0.3.9, windows only): Provides access to Windows system calls.

## Getting Started

### Prerequisites

Make sure you have the following installed on your system:

- **Rust toolchain**: You can install it from [here](https://www.rust-lang.org/tools/install).

This application is built for **Windows** using the `native-windows-gui` crate, so it will only run on Windows systems.

### Building the Project

1. Clone this repository:

    ```bash
    git clone https://github.com/your-username/sha3_hash_app.git
    cd sha3_hash_app
    ```

2. Build the application using `cargo`:

    ```bash
    cargo build
    ```

3. Run the application:

    ```bash
    cargo run
    ```

4. To build the project for release:

    ```bash
    cargo build --release
    ```

   The executable will be located in the `target/release` directory.

### Usage

1. After running the application, you will see a GUI window with an input box, two buttons, and an output box.
2. Enter the text you want to hash in the input field.
3. Click **"Generate Hash"** to compute the SHA3-512 hash. The hash will appear in the output box.
4. If you want to clear the output, click the **"Clear"** button.




## Code Overview

The application consists of a simple event-driven GUI:

- **Input Field**: Allows the user to input text to be hashed.
- **Generate Button**: Generates the SHA3-512 hash of the input text.
- **Clear Button**: Clears the output box.
- **Output Box**: Displays the resulting hash in a read-only text box.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contributions

Contributions, bug reports, and feature requests are welcome! Feel free to open issues and pull requests on the [GitHub repository](https://github.com/your-username/sha3_hash_app).

