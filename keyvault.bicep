param location string
param name string

resource keyvault 'Microsoft.KeyVault/vaults@2021-11-01-preview' = {
  name: name
  location: location
  properties: {
    tenantId: subscription().tenantId
    enableSoftDelete:true
    enablePurgeProtection:true
    accessPolicies:[]
    sku:{
      name:'premium'
      family: 'A'
    }
  }
}
