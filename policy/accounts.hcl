path "hdwallet/account/{{identity.entity.name}}/path" {
    capabilities = ["read"]
}

path "hdwallet/account/{{identity.entity.name}}/sign-tx"{
    capabilities = ["create"]
}

path "hdwallet/account/{{identity.entity.name}}/sign"{
    capabilities = ["create"]
}