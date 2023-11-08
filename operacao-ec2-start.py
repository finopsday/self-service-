import boto3
import botocore.exceptions
import json
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Configure o cliente SES com suas credenciais
ses = boto3.client('ses', region_name='us-east-1')  # Substitua 'us-east-1' pela região desejada

target_accounts = ['ACCOUNTID', 'ACCOUNTID']

ec2 = boto3.client('ec2')

def send_email(subject, message):
    # Substitua pelos seus endereços de e-mail
    sender = "SEU E-MAIL AQUI"
    recipient = "SEU E-MAIL AQUI"

    ses.send_email(
        Source=sender,
        Destination={
            'ToAddresses': [recipient],
        },
        Message={
            'Subject': {
                'Data': subject,
            },
            'Body': {
                'Text': {
                    'Data': message,
                },
            },
        }
    )

def get_instances_with_tag(tag_name, tag_value, account):
    project_tag = f"{tag_name}:{tag_value}"
    instances = []

    for target_account in target_accounts:
        if target_account == account:
            role_to_assume_arn = f"arn:aws:iam::{target_account}:role/roleStartStop"
            sts_client = boto3.client('sts')
            assumed_role = sts_client.assume_role(RoleArn=role_to_assume_arn, RoleSessionName="AssumeRoleSession")

            assumed_session = boto3.Session(
                aws_access_key_id=assumed_role['Credentials']['AccessKeyId'],
                aws_secret_access_key=assumed_role['Credentials']['SecretAccessKey'],
                aws_session_token=assumed_role['Credentials']['SessionToken']
            )

            ec2 = assumed_session.client('ec2')

            filters = [
                {
                    'Name': f'tag:{tag_name}',
                    'Values': [tag_value]
                }
            ]

            response = ec2.describe_instances(Filters=filters)

            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    instances.append(instance['InstanceId'])

    return instances

def start_instances(instance_ids):
    success_messages = []
    error_messages = []

    for instance_id in instance_ids:
        try:
            response = ec2.start_instances(InstanceIds=[instance_id])
        except botocore.exceptions.ClientError as e:
            logger.error(f"Falha ao iniciar a instância '{instance_id}': {e}")
            error_messages.append(f"Falha ao iniciar a instância '{instance_id}': {e}")
        else:
            logger.info(f"A instância '{instance_id}' foi iniciada com sucesso.")
            success_messages.append(f"A instância '{instance_id}' foi iniciada com sucesso.")

    return success_messages, error_messages

def lambda_handler(event, context):
    response_body = json.dumps(event['body']).replace('\\', ' ')

    if event['httpMethod'] == 'POST':
        try:
            request_body = json.loads(event['body'])
            tag = request_body.get('tag')
            account = request_body.get('account')

            # Verifique se a tag está presente na solicitação
            if not tag:
                error_message = "A tag não foi fornecida na solicitação."
                logger.error(error_message)
                send_email("Erro na Solicitação", error_message)
                return {
                    "statusCode": 400,
                    "body": json.dumps({
                        "status": "error",
                        "message": error_message
                    }, indent=2)
                }
            
            key, value = tag.split(':')

            # Verifica se a conta especificada corresponde a uma das contas alvo
            if account in target_accounts:
                instance_ids = get_instances_with_tag(key, value, account)
                if instance_ids:
                    success_messages, error_messages = start_instances(instance_ids)
                    if success_messages:
                        email_message = "\n".join(success_messages)
                        send_email("Sucesso ao Iniciar Instâncias", email_message)
                    if error_messages:
                        email_message = "\n".join(error_messages)
                        send_email("Falha ao Iniciar Instâncias", email_message)

                    return {
                        "statusCode": 200,
                        "body": response_body
                    }
                else:
                    error_message = "Nenhuma instância encontrada com a tag especificada."
                    logger.error(error_message)
                    send_email("Nenhuma Instância Encontrada", error_message)
                    return {
                        "statusCode": 200,
                        "body": json.dumps({
                            "status": "error",
                            "message": error_message
                        }, indent=2)
                    }
            else:
                error_message = "A conta especificada não é uma conta alvo válida."
                logger.error(error_message)
                send_email("Conta Inválida", error_message)
                return {
                    "statusCode": 400,
                    "body": json.dumps({
                        "status": "error",
                        "message": error_message
                    }, indent=2)
                }
        except json.JSONDecodeError:
            error_message = "Falha ao decodificar o corpo da solicitação."
            logger.error(error_message)
            send_email("Erro na Solicitação", error_message)
            return {
                "statusCode": 400,
                "body": json.dumps({
                    "status": "error",
                    "message": error_message
                }, indent=2)
            }
        except ValueError as e:
            error_message = str(e)
            logger.error(error_message)
            send_email("Erro na Solicitação", error_message)
            return {
                "statusCode": 400,
                "body": json.dumps({
                    "status": "error",
                    "message": error_message
                }, indent=2)
            }
    return {
        "statusCode": 400,
        "body": json.dumps({
            "status": "error",
            "message": "Método não suportado."
        }, indent=2)
    }
