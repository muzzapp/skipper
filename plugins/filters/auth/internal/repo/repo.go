package repo

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/expression"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

const (
	gsi1 = "GSI1"
)

type Repo struct {
	client *dynamodb.Client
	table  string
}

func NewRepo(table string) *Repo {
	cfg, _ := config.LoadDefaultConfig(context.Background())
	client := dynamodb.NewFromConfig(cfg)

	return &Repo{
		client: client,
		table:  table,
	}
}

// Model B is variable
// If it's '1' then it's a regular login
// If it's anything else, it's an admin spoof token that we'll send downstream
type Model struct {
	AccountUid         string `dynamodbav:"A"`
	B                  string
	UDID               string `dynamodbav:"C"`
	Token              string `dynamodbav:"D"`
	AccountId          uint32
	MarriageProfileUid string
	MarriageProfileId  uint32
	SocialUid          string
}

func (d *Repo) FindByUdidAndToken(udid string, token string) (*Model, error) {
	expr, err := expression.NewBuilder().
		WithKeyCondition(
			expression.Key("C").Equal(expression.Value(udid)).
				And(expression.Key("D").Equal(expression.Value(token))),
		).
		Build()

	item, err := d.client.Query(context.Background(), &dynamodb.QueryInput{
		TableName:                 aws.String(d.table),
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		KeyConditionExpression:    expr.KeyCondition(),
	})
	if err != nil {
		return nil, err
	}

	if len(item.Items) == 0 {
		return nil, nil
	}

	var am Model
	err = attributevalue.UnmarshalMap(item.Items[0], &am)
	if err != nil {
		return nil, err
	}

	return &am, nil
}
