# **WEP40 Cracking with FMS Attack**

### **Problem Statement**
The goal of this project is to demonstrate the vulnerabilities in the WEP40 wireless security protocol using the **Fluhrer, Mantin, and Shamir (FMS) attack**. The WEP protocol, which uses the RC4 stream cipher, suffers from predictable keystream biases caused by weak Initialization Vectors (IVs). Our project focuses on re-implementing the FMS attack to capture WEP packets, recover the WEP key byte by byte, and demonstrate how this old protocol can be cracked within minutes.


## Requirements
- **Python 3.11** or higher
- **Scapy** for handling `.pcap` files
  - Install Scapy via pip:
    ```bash
    pip install scapy
    ```


### **Generating WEP Packets**
To produce a CSV file containing packets with a specific key, run the following command:

```bash
python3 packets_gen.py <key in hex format>
```

For example
```bash
python3 packets_gen.py AAAAAAAAAA
```


This produces WEP packets with the key ```0xAAAAAAAAAA```. The key must have a maximum length of 5 bytes. 
Without specifying an argument, the script will default to using the WEP key ```0x4341434343``` and save the output to packets.csv.

You can also specify a custom output filename using the ```--output_filename=<filename>``` argument:
```bash
python3 packets_gen.py <key in hex format> --output_filename=<your_custom_filename.csv>
```

For example:
```bash
python3 packets_gen.py AAAAAAAAAA --output_filename=wep_packets.csv
```
This command uses the WEP key 0xAAAAAAAAAA and saves the packets to wep_packets.csv. If --output_filename is not provided, the default packets.csv is used.


#### **To crack the WEP password, run:**
```bash 
python3 fms_attack.py --file_path="custom_packets.csv"
```

## Command-line Arguments

The script accepts two optional arguments:

- `--from_wep`: A flag to indicate if the input file is a `.pcap` file. If specified, the script will load packets using the `.pcap` format.
- `--file_path`: A string argument to specify the path of the input file. If not provided, the default file path will be:
  - `file8.pcap` when `--from_wep` is used.
  - `packets.csv` otherwise.
### **References**
- **Fluhrer, Mantin, and Shamir attack - Wikipedia**  
  [Wikipedia Link](https://en.wikipedia.org/wiki/Fluhrer,_Mantin_and_Shamir_attack)
- **"Security Analysis of Wi-Fi Networks Using WEP Encryption" - ScienceDirect**  
  [ScienceDirect Link](https://www.sciencedirect.com/science/article/pii/S1877050921005603)
