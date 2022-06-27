param location string
param name string

var latestRelease = 'https://github.com/rbickel/KeyVault.CertificateAuthority/releases/download/0.1.3/KeyVault.CertificateAuthority.0.1.3.zip'
var storageAccountName = uniqueString(resourceGroup().id)

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

resource storageAccount 'Microsoft.Storage/storageAccounts@2021-08-01' = {
  name: storageAccountName
  location: location
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'Storage'
}

resource hostingPlan 'Microsoft.Web/serverfarms@2021-03-01' = {
  name: '${name}-func-plan'
  location: location
  sku: {
    name: 'Y1'
    tier: 'Dynamic'
  }
  properties: {}
}

resource function 'Microsoft.Web/sites@2021-03-01' = {
  name: '${name}-func'
  location: location
  kind: 'functionapp'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: hostingPlan.id
    siteConfig: {
      appSettings: [
        {
          name: 'AzureWebJobsStorage'
          value: 'DefaultEndpointsProtocol=https;AccountName=${storageAccountName};EndpointSuffix=${environment().suffixes.storage};AccountKey=${storageAccount.listKeys().keys[0].value}'
        }
        {
          name: 'WEBSITE_CONTENTAZUREFILECONNECTIONSTRING'
          value: 'DefaultEndpointsProtocol=https;AccountName=${storageAccountName};EndpointSuffix=${environment().suffixes.storage};AccountKey=${storageAccount.listKeys().keys[0].value}'
        }
        {
          name: 'WEBSITE_CONTENTSHARE'
          value: '${name}-func'
        }
        {
          name: 'FUNCTIONS_EXTENSION_VERSION'
          value: '~4'
        }
        {
          name: 'FUNCTIONS_WORKER_RUNTIME'
          value: 'dotnet'
        }
        {
          name: 'WEBSITE_RUN_FROM_PACKAGE '
          value: latestRelease
        }
        {
          name: 'DefaultKeyVaultUri '
          value: keyvault.properties.vaultUri
        }        
        {
          name: 'DefaultKeyCACertificate'
          value: 'RootCA'
        }
        {
          name: 'DefaultCertificateDuration'
          value: '365'
        }        
      ]
      ftpsState: 'Disabled'
      minTlsVersion: '1.2'
    }
    httpsOnly: true
  }
}

resource eventGridTopic 'Microsoft.EventGrid/systemTopics@2021-12-01' = {
  name: '${name}-topic'
  location: location
  properties: {
    source: keyvault.id
    topicType: 'Microsoft.KeyVault.vaults'
  }
}

resource eventGridTopicSubscription 'Microsoft.EventGrid/systemTopics/eventSubscriptions@2021-12-01' ={
  name: '${name}-topic-subscription'
  parent: eventGridTopic
  properties: {
    eventDeliverySchema: 'EventGridSchema'
    destination: {
      endpointType: 'AzureFunction'
      properties: {
        maxEventsPerBatch: 1
        preferredBatchSizeInKilobytes: 64
        resourceId: '${function.id}/functions/RenewTlsCertificate'
      }
    }
    filter:{
      includedEventTypes:[
        'Microsoft.KeyVault.CertificateNearExpiry'
        'Microsoft.KeyVault.CertificateExpired'
      ]
    }
    retryPolicy:{
      maxDeliveryAttempts: 5
      eventTimeToLiveInMinutes: 1440
    }
  }
}

resource keyvaultPolicy 'Microsoft.KeyVault/vaults/accessPolicies@2021-11-01-preview' = {
  name: 'add'
  parent: keyvault
  properties: {
    accessPolicies: [
      {
        objectId: function.identity.principalId
        tenantId: function.identity.tenantId
        permissions: {
          certificates: [
            'all'
          ]
          keys: [
            'sign'
          ]
        }
      }
    ]
  }
}

output functionKeys string = listkeys(concat(function.id, '/host/default'), '2022-03-01').functionKeys.default
