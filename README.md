# Storage Account Blobs to Azure Sentinel
This custom Azure Sentinel Data connector ingests Azure Storage Account Blobs to Azure Sentinel

![Auth0LogsIngestionFlow](./images/Auth0LogsIngestionFlow.PNG) 

## **Pre-requisites**

1. Click on Deploy to Azure (For both Commercial & Azure GOV)  
   <a href="https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fandedevsecops%2FAuth0Logs-Connector%2Fmain%2Fazuredeploy_auth0.json" target="_blank">
    <img src="https://aka.ms/deploytoazurebutton"/>
	</a>
  

2. Select the preferred **Subscription**, **Resource Group** and **Location**  
   **Note**  
   Best practice : Create new Resource Group while deploying - all the resources of your custom Data connector will reside in the newly created Resource 
   Group
   
3. Enter the following value in the ARM template deployment
	```
	"Function App Name": Function App Name
	"Workspace Id": Azure Log Analytics Workspace Id​
	"Workspace Key": Azure Log Analytics Workspace Key
	```

## Configuration Steps to Ingest Auth0 Logs

1. Pre-requisites deployment step created Azure Storage Account called <<Function App Name>><<uniqueid>>sa and "logssource" container, 

3. From the Storage Account Settings section, click Access keys. Copy either storage account key value; you will need it in the next section

4. Configure [Export Logs to Azure Blob Storage](https://auth0.com/docs/extensions/export-logs-to-azure-blob-storage#configure-the-extension) extension
