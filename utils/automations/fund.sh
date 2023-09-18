# fund.sh

bitcoin-cli -regtest -rpcpassword=devnet -rpcuser=devnet generatetoaddress 1 bcrt1phvt5tfz4hlkth0k7ls9djweuv9rwv5a0s5sa9085umupftnyalxq0zx28d # signer 1
bitcoin-cli -regtest -rpcpassword=devnet -rpcuser=devnet generatetoaddress 1 bcrt1pdsavc4yrdq0sdmjcmf7967eeem2ny6vzr4f8m7dyemcvncs0xtwsc85zdq # signer 2
bitcoin-cli -regtest -rpcpassword=devnet -rpcuser=devnet generatetoaddress 101 bcrt1pa4w2alr6x7tuxwg7anpep90rzn09sxhwppxvq9xt99p20lwqmlcqz9q8e3 # signer 3

bitcoin-cli -regtest -rpcpassword=devnet -rpcuser=devnet generatetoaddress 1 BCRT1P8M4KHK8A06CUCAWGPPQ3GDKEXTH7MZF6DGW54KZ67TKFQ3RCUU5QNKHUDG # signer 1 tweaked
bitcoin-cli -regtest -rpcpassword=devnet -rpcuser=devnet generatetoaddress 1 BCRT1P6HNYZU0USW758H2F04GMWDGYWXAK9PAMA9S7AQ7NZEMXVGG0JTHSN9DNZN # signer 2 tweaked
bitcoin-cli -regtest -rpcpassword=devnet -rpcuser=devnet generatetoaddress 101 BCRT1P6DDX97EN6YMWLHCF4RA7WK3KEXD0U5DPCEV2YTXLRXFZMVZ67GUQDLARFQ # signer 3 tweaked

bitcoin-cli -regtest -rpcpassword=devnet -rpcuser=devnet generatetoaddress 1 BCRT1PQCHMH7V5KW2F0XYR6Y6S6C7A68MQUFS6MSTS34HWUE8GQXVRN7QS5V6AFV # script address - signer 1
bitcoin-cli -regtest -rpcpassword=devnet -rpcuser=devnet generatetoaddress 1 BCRT1PTW0UU2GHXUSFTV5AL8AKQKLZ34Y69H4PNL5057CD3328Q842K9XSMEE5S3 # script address - signer 2
bitcoin-cli -regtest -rpcpassword=devnet -rpcuser=devnet generatetoaddress 101 BCRT1PRAFYSZ9H3CYLVR9YWJD28NNYPPFGK0P6PKKXFU9VNKE02ND8WRRS596P3F # script address - signer 3