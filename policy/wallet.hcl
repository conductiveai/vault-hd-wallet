path "hdwallet/wallet" {
    capabilities = ["create", "read"]
}

path "hdwallet/wallet/*" {
    capabilities = ["create", "read"]
}

path "hdwallet/account"{
    capabilities = ["create", "read"]
}

path "hdwallet/account/*"{
    capabilities = ["create", "read"]
}