// implementing the use the AWS SDK v3 
import { DynamoDBClient, GetItemCommand } from '@aws-sdk/client-dynamodb';

// initialize the DynamoDB client
const client = new DynamoDBClient({ region: 'us-east-1' }); //  region

export const handler = async (event) => {
  // extracting the ID from the pathParameters for product by ID 
  const { id } = event.pathParameters; //  ID is passed in the path as /product/{id}

  const params = {
    TableName: 'Products',  // DynamoDB table
    Key: {
      id: { S: id },  // 'id' is the primary key attribute name, and 'S' denotes a string type
    },
  };

  try {
    // fetching the item from the DynamoDB table
    const data = await client.send(new GetItemCommand(params));
    
    if (data.Item) {
      return {
        statusCode: 200,
        body: JSON.stringify(data.Item),
        headers: {
          'Content-Type': 'application/json',
        },
      };
    } else {
      // if no item is found, returning a 404 status with an empty array
      return {
        statusCode: 404,
        body: JSON.stringify([]), // Return an empty array
        headers: {
          'Content-Type': 'application/json',
        },
      };
    }
  } catch (error) {
    console.error('Error fetching item by ID:', error);
    return {
      statusCode: 500,
      body: JSON.stringify({ errorCode: 'ERR_SERVER_ERROR', message: 'Error fetching item.' }),
      headers: {
        'Content-Type': 'application/json',
      },
    };
  }
};
