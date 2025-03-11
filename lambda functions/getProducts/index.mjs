// comment given - using the AWS SDK v3 
import { DynamoDBClient, ScanCommand } from '@aws-sdk/client-dynamodb';

// initialising the DynamoDB client
const client = new DynamoDBClient({ region: 'us-east-1' }); // AWS region set 

export const handler = async (event) => {
  const params = {
    TableName: 'Products',  //  dynamoDB table is used
  };

  try {
    // it fetch all products from the DynamoDB table Products
    const data = await client.send(new ScanCommand(params));

    // returning  the items in the response if found 
    return {
      statusCode: 200,
      body: JSON.stringify(data.Items || []), // ensuring an empty array is returned if no items are found
      headers: {
        'Content-Type': 'application/json',
      },
    };
  } catch (error) {
    console.error('Error fetching products:', error);
    return {
      statusCode: 500,
      body: JSON.stringify({ errorCode: 'ERR_SERVER_ERROR', message: 'Error fetching products.' }),
      headers: {
        'Content-Type': 'application/json',
      },
    };
  }
};
