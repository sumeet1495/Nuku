import { DynamoDBClient, ScanCommand } from '@aws-sdk/client-dynamodb';

// in this initialize the DynamoDB client
const client = new DynamoDBClient({ region: 'us-east-1' });

export const handler = async (event) => {
  console.log('Event:', JSON.stringify(event, null, 2)); // logging the event object

  const queryParameters = event.queryStringParameters || {};
  const searchString = queryParameters.searchString || '';

  if (!searchString) {
    return {
      statusCode: 400,
      body: JSON.stringify({ error: 'searchString query parameter is required' }),
      headers: {
        'Content-Type': 'application/json',
      },
    };
  }
  const params = {
    TableName: 'Products',
    FilterExpression: 'contains(#name_lowercase, :searchString)',
    ExpressionAttributeNames: {
      '#name_lowercase': 'name_lowercase',
    },
    ExpressionAttributeValues: {
      ':searchString': { S: searchString.toLowerCase() }, // ensuring search string is in lowercase
    },
  };

  try {
    const data = await client.send(new ScanCommand(params));

    // Transform the DynamoDB items into a standard JSON format
    const items = data.Items.map(item => {
      return {
        id: item.id.S,
        name: item.name.S,
        description: item.description.S,
        category: item.category.S,
        price: parseFloat(item.price.N),
        stock_quantity: parseInt(item.stock_quantity.N),
        image_url: item.image_url.S,
        supplier: item.supplier.S,
        created_at: item.created_at.S,
        updated_at: item.updated_at.S
      };
    });

    return items; // directly return the array of items
  } catch (error) {
    console.error('Error searching items:', error);
    return {
      errorCode: 'ERR_SERVER_ERROR',
      message: 'Error searching items.',
    };
  }
};
