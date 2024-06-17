# Running Tests for NKS

Firstly, you need to have a Hashicorp Vault server and the backend server running.
You can find instructions and code [here](https://github.com/cep-sose2024/rhein_sec)
Then you need to clone this directory and run the following commands:

1. **Open your terminal.**
2. **Navigate to the root directory of the project using the `cd` command. Replace `path/to/your/project` with the actual path to your project:**
    ```bash
    cd path/to/the/project
    ```
3. **To execute the demo, run the following command:**
    ```bash
    cargo run --features hcvault, crypto_layer --address https://your_backend_address/
    ```