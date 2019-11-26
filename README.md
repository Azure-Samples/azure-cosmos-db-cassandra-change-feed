---
page_type: sample
languages:
- csharp
products:
- azure
description: "Azure Cosmos DB's API for Cassandra - Change Feed Sample"
urlFragment: cassandra-change-feed
---

# Using the Change Feed with Azure Cosmos DB's API for Cassandra
Azure Cosmos DB is Microsoft's globally distributed multi-model database service. You can quickly create and query document, table, key-value, and graph databases, all of which benefit from the global distribution and horizontal scale capabilities at the core of Azure Cosmos DB. 
This quick start demonstrates how to interact with the Change Feed API using Azure Cosmos DB's API for Cassandra

## Running this sample
* Before you can run this sample, you must have the following perquisites:
	* An active Azure Cassandra API account - If you don't have an account, refer to the [Create Cassandra API account](https://docs.microsoft.com/en-us/azure/cosmos-db/create-cassandra-dotnet). 
	* [Microsoft Visual Studio](https://www.visualstudio.com).
	* [Git](http://git-scm.com/).

1. Clone this repository using `git clone https://github.com/azure-samples/azure-cosmos-db-cassandra-change-feed.git`

2. Open the CassandraChangeFeedSample.sln solution and install the Cassandra .NET driver. Use the .NET Driver's NuGet package. From the Package Manager Console window in Visual Studio:

```bash
PM> Install-Package CassandraCSharpDriver
```

3. Next, configure the endpoints in **Program.cs** for both DataGenerator and ChangeFeedSample projects:

```
private const string UserName = "<FILLME>"; 
private const string Password = "<FILLME>";
private const string CassandraContactPoint = "<FILLME>"; //  DnsName
```
4. Compile the project.

5. Set ChangeFeedSample as the startup project, run it. This will create Keyspace and table, and start querying the change feed (initially there will be zero documents returned).

6. While ChangeFeedSample is running, open the solution file again in a new Visual Studio instance. This time set DataGenerator as the start up project, and run it. 

7. Go back to your open run window for ChangeFeedSample. In each iteration, the Change Feed resumes from the last point at which changes were read. This could be used in a streaming or event sourcing scenario. 


## About the code
The code included in this sample is intended to demonstrate how to interract with the Change Feed using Azure Cosmos DB's API for Cassandra. The sample shows the Change Feed being queried iteratively, using paging state. The idea of the demo is to show the sample running, while another application (DataGenerator) is writing records to the same Cassandra table.

## More information

- [Azure Cosmos DB](https://docs.microsoft.com/azure/cosmos-db/introduction)
- [Cassandra DB](http://cassandra.apache.org/)
