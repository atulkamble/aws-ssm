Awesome, Atul! Here’s a **repo-ready, hands-on AWS Systems Manager practice project** with runnable code, CLI steps, and automation docs. It’s split into small “labs” so you (or trainees) can do them independently or as a full end-to-end project.

---

# 🛠️ AWS Systems Manager (SSM) – Practice Codes, Steps & Project

## What you’ll build

1. **Bastion-less EC2 access** with **Session Manager**
2. **Zero-downtime app config** via **Parameter Store** + app reload
3. **Patch management** with **Patch Manager** + **Maintenance Window**
4. **Golden AMI backups** via **Automation Runbook**
5. **Fleet bootstrap** with **Run Command** + State Manager association
6. **Inventory & compliance** reporting
7. **OpsCenter** incident created from a CloudWatch alarm (bonus)

---

## 📁 Repo structure

```
aws-ssm-practice/
├─ README.md
├─ terraform/
│  ├─ main.tf
│  ├─ variables.tf
│  ├─ outputs.tf
├─ iam/
│  ├─ ssm-ec2-instance-profile.json
│  ├─ ssm-automation-assume-role.json
│  └─ ssm-automation-passrole-policy.json
├─ ssm-documents/
│  ├─ BootstrapLinuxApp.yaml           # Command document (schema 2.2)
│  ├─ PatchAndReboot.yaml              # Automation (schema 0.3)
│  └─ AmiBackup.yaml                   # Automation (schema 0.3)
├─ scripts/
│  ├─ install_ssm_agent.sh
│  ├─ app_bootstrap.sh
│  └─ verify_ssm.sh
├─ app/
│  ├─ server.py                         # simple Flask app reads SSM param
│  └─ requirements.txt
└─ maintenance/
   └─ mw-patch-window.json
```

---

## ✅ Prereqs

* AWS CLI v2 configured
* An AWS account with permissions to create IAM roles, EC2, SSM
* Key pair for SSH (only for fallback), but **we’ll use Session Manager**
* One **Amazon Linux 2023** AMI (default in Terraform below)

---

# 1) Core Infra (Terraform)

**terraform/main.tf** (minimal but production-ish)

```hcl
terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

provider "aws" {
  region = var.region
}

# VPC (default) to keep it short; for training, a custom VPC module is great.

resource "aws_iam_role" "ec2_ssm_role" {
  name               = "${var.name}-ec2-ssm-role"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
}

data "aws_iam_policy_document" "ec2_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals { type = "Service", identifiers = ["ec2.amazonaws.com"] }
  }
}

# Attach AWS-managed policies for SSM access
resource "aws_iam_role_policy_attachment" "ec2_ssm_core" {
  role       = aws_iam_role.ec2_ssm_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "ec2_profile" {
  name = "${var.name}-ec2-profile"
  role = aws_iam_role.ec2_ssm_role.name
}

resource "aws_security_group" "sg" {
  name        = "${var.name}-sg"
  description = "Allow HTTP for demo"
  vpc_id      = data.aws_vpc.default.id

  ingress { description="HTTP"; from_port=80; to_port=80; protocol="tcp"; cidr_blocks=["0.0.0.0/0"] }
  egress  { from_port=0; to_port=0; protocol="-1"; cidr_blocks=["0.0.0.0/0"] }
}

data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["137112412989"] # Amazon
  filter { name="name"; values=["al2023-ami-*-x86_64"] }
}

data "aws_vpc" "default" { default = true }
data "aws_subnets" "default" { filter { name="vpc-id"; values=[data.aws_vpc.default.id] } }

resource "aws_instance" "web" {
  ami                         = data.aws_ami.al2023.id
  instance_type               = "t3.micro"
  subnet_id                   = data.aws_subnets.default.ids[0]
  iam_instance_profile        = aws_iam_instance_profile.ec2_profile.name
  vpc_security_group_ids      = [aws_security_group.sg.id]
  user_data                   = file("${path.module}/../scripts/app_bootstrap.sh")
  tags = { Name = "${var.name}-web" }
}

output "instance_id" { value = aws_instance.web.id }
output "public_ip"   { value = aws_instance.web.public_ip }
```

**terraform/variables.tf**

```hcl
variable "region" { type = string  default = "us-east-1" }
variable "name"   { type = string  default = "ssm-practice" }
```

**scripts/app\_bootstrap.sh**

```bash
#!/usr/bin/env bash
set -euo pipefail

dnf update -y || yum update -y || true
# AL2023 has SSM Agent by default; ensure running:
systemctl enable amazon-ssm-agent || true
systemctl start amazon-ssm-agent || true

# Install Python + Flask demo app
dnf install -y python3 git || yum install -y python3 git
python3 -m pip install --upgrade pip

cat >/opt/app.service <<'EOF'
[Unit]
Description=Flask app reading SSM parameter
After=network.target

[Service]
User=root
WorkingDirectory=/opt/app
Environment="PARAM_NAME=/app/config/message"
ExecStart=/usr/bin/python3 /opt/app/server.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF

mkdir -p /opt/app
cat >/opt/app/requirements.txt <<EOF
flask
boto3
EOF

python3 -m pip install -r /opt/app/requirements.txt

cat >/opt/app/server.py <<'PY'
from flask import Flask
import boto3, os

app = Flask(__name__)
ssm = boto3.client('ssm', region_name=os.getenv("AWS_REGION", "us-east-1"))
PARAM_NAME = os.getenv("PARAM_NAME", "/app/config/message")

def get_message():
    try:
        resp = ssm.get_parameter(Name=PARAM_NAME, WithDecryption=True)
        return resp["Parameter"]["Value"]
    except Exception as e:
        return f"Param read error: {e}"

@app.route("/")
def home():
    return {"app":"ssm-demo","message": get_message()}

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
PY

chmod 644 /opt/app/server.py
systemctl daemon-reload
systemctl enable app.service
systemctl start app.service
```

**Deploy:**

```bash
cd terraform
terraform init
terraform apply -auto-approve
```

**Verify SSM connection:**

```bash
aws ssm describe-instance-information --query "InstanceInformationList[].InstanceId"
```

---

# 2) Lab A – Session Manager (bastion-less)

### Start a session

```bash
INSTANCE_ID=$(terraform -chdir=terraform output -raw instance_id)
aws ssm start-session --target "$INSTANCE_ID"
```

### Port-forward (if your app ran on 5000, example)

```bash
aws ssm start-session --target "$INSTANCE_ID" \
  --document-name AWS-StartPortForwardingSession --parameters "portNumber=80,localPortNumber=8080"
# Open http://localhost:8080
```

### Troubleshooting

```bash
# On instance:
systemctl status amazon-ssm-agent
tail -n 100 /var/log/amazon/ssm/amazon-ssm-agent.log
```

---

# 3) Lab B – Parameter Store for dynamic config

### Create a parameter (no secrets)

```bash
aws ssm put-parameter \
  --name "/app/config/message" \
  --type "String" \
  --value "Hello from Parameter Store!" \
  --overwrite
```

### Verify from app (curl public IP)

```bash
PUBLIC_IP=$(terraform -chdir=terraform output -raw public_ip)
curl http://$PUBLIC_IP/
```

Update the value and re-curl to see live change:

```bash
aws ssm put-parameter --name "/app/config/message" --type "String" --value "Updated at $(date)" --overwrite
curl http://$PUBLIC_IP/
```

> For secrets, use `--type SecureString` and KMS.

---

# 4) Lab C – Run Command + State Manager (bootstrap fleets)

### Command document (schema 2.2)

**ssm-documents/BootstrapLinuxApp.yaml**

```yaml
schemaVersion: '2.2'
description: Bootstrap Linux app with packages and message file
parameters:
  Message:
    type: String
    default: "Deployed via Run Command"
    description: Message to write
mainSteps:
  - action: aws:runShellScript
    name: Bootstrap
    inputs:
      runCommand:
        - |
          set -e
          echo "Installing jq"
          (dnf install -y jq || yum install -y jq) >/dev/null 2>&1 || true
          echo "{{ Message }}" > /opt/bootstrap_message.txt
          cat /opt/bootstrap_message.txt
```

**Create document & run:**

```bash
aws ssm create-document \
  --name "BootstrapLinuxApp" \
  --document-type "Command" \
  --content file://ssm-documents/BootstrapLinuxApp.yaml

aws ssm send-command \
  --instance-ids "$INSTANCE_ID" \
  --document-name "BootstrapLinuxApp" \
  --parameters "Message=Hello from SSM Run Command" \
  --comment "Initial bootstrap" \
  --output-s3-bucket-name "" \
  --query "Command.CommandId" --output text
```

**State Manager Association** (keeps config drift-free):

```bash
aws ssm create-association \
  --name "BootstrapLinuxApp" \
  --targets "Key=InstanceIds,Values=$INSTANCE_ID" \
  --schedule-expression "rate(30 minutes)" \
  --parameters "Message=Compliance check at $(date +%F)"
```

---

# 5) Lab D – Patch Manager + Maintenance Window

**Create a patch baseline** and **maintenance window**, then register a **task**.

*Minimal JSON example:*

**maintenance/mw-patch-window\.json**

```json
{
  "Name": "PatchWindow",
  "Schedule": "cron(0 18 ? * SAT *)",
  "ScheduleTimezone": "Asia/Kolkata",
  "Duration": 2,
  "Cutoff": 1,
  "AllowUnassociatedTargets": false
}
```

**Commands:**

```bash
# Create maintenance window (Saturdays 18:00 IST)
aws ssm create-maintenance-window --cli-input-json file://maintenance/mw-patch-window.json

MW_ID=$(aws ssm describe-maintenance-windows --query "WindowIdentities[?Name=='PatchWindow'].WindowId" --output text)

# Register target (our instance)
aws ssm register-target-with-maintenance-window \
  --window-id $MW_ID \
  --targets "Key=InstanceIds,Values=$INSTANCE_ID" \
  --owner-information "Patch Linux fleet" \
  --name "LinuxTargets" \
  --resource-type "INSTANCE"

# Register task using AWS-RunPatchBaseline
aws ssm register-task-with-maintenance-window \
  --window-id $MW_ID \
  --targets "Key=InstanceIds,Values=$INSTANCE_ID" \
  --task-arn "AWS-RunPatchBaseline" \
  --task-type "RUN_COMMAND" \
  --task-invocation-parameters '{"RunCommand":{"Parameters":{"Operation":["Install"]}}}' \
  --max-concurrency "1" \
  --max-errors "1" \
  --name "PatchTask"
```

Run on demand anytime:

```bash
aws ssm send-command --instance-ids "$INSTANCE_ID" \
  --document-name "AWS-RunPatchBaseline" \
  --parameters "Operation=Install"
```

---

# 6) Lab E – Automation Runbooks

## (E1) Patch + reboot Automation

**ssm-documents/PatchAndReboot.yaml**

```yaml
description: "Run patch baseline and reboot if required"
schemaVersion: '0.3'
assumeRole: "{{ AutomationAssumeRole }}"
parameters:
  InstanceId:
    type: String
  AutomationAssumeRole:
    type: String
mainSteps:
  - name: RunPatch
    action: aws:runCommand
    inputs:
      DocumentName: AWS-RunPatchBaseline
      InstanceIds:
        - "{{ InstanceId }}"
      Parameters:
        Operation: [ "Install" ]
  - name: RebootIfNeeded
    action: aws:branch
    inputs:
      Choices:
        - NextStep: Reboot
          Variable: "{{ aws:runCommand[RunPatch].Status }}"
          StringEquals: "Success"
      Default: End
  - name: Reboot
    action: aws:runCommand
    inputs:
      DocumentName: AWS-RunShellScript
      InstanceIds:
        - "{{ InstanceId }}"
      Parameters:
        commands:
          - "sudo reboot || true"
  - name: End
    action: aws:sleep
    inputs:
      Duration: PT5M
```

Create & execute:

```bash
aws ssm create-document \
  --name "PatchAndReboot" \
  --document-type "Automation" \
  --content file://ssm-documents/PatchAndReboot.yaml

# Create Automation assume role (see IAM snippets below) and pass here:
AUTOMATION_ROLE_ARN="arn:aws:iam::<ACCOUNT_ID>:role/ssm-automation-exec"
aws ssm start-automation-execution \
  --document-name "PatchAndReboot" \
  --parameters "InstanceId=$INSTANCE_ID,AutomationAssumeRole=$AUTOMATION_ROLE_ARN"
```

## (E2) AMI backup Automation

**ssm-documents/AmiBackup.yaml**

```yaml
description: "Create an AMI backup with timestamp and tag"
schemaVersion: '0.3'
assumeRole: "{{ AutomationAssumeRole }}"
parameters:
  InstanceId:
    type: String
  AutomationAssumeRole:
    type: String
  AmiNamePrefix:
    type: String
    default: "golden-ami"
mainSteps:
  - name: CreateImage
    action: aws:createImage
    inputs:
      InstanceId: "{{ InstanceId }}"
      ImageName: "{{ AmiNamePrefix }}-{{ global:DATE_TIME }}"
      NoReboot: true
  - name: TagImage
    action: aws:createTags
    inputs:
      ResourceType: "EC2"
      ResourceIds:
        - "{{ CreateImage.ImageId }}"
      Tags:
        - Key: "CreatedBy"
          Value: "SSM-Automation"
        - Key: "Role"
          Value: "backup"
```

Create & run:

```bash
aws ssm create-document \
  --name "AmiBackup" \
  --document-type "Automation" \
  --content file://ssm-documents/AmiBackup.yaml

aws ssm start-automation-execution \
  --document-name "AmiBackup" \
  --parameters "InstanceId=$INSTANCE_ID,AutomationAssumeRole=$AUTOMATION_ROLE_ARN,AmiNamePrefix=ssm-demo"
```

---

# 7) Lab F – Inventory & Compliance

Enable inventory on the instance:

```bash
aws ssm put-inventory \
  --instance-id "$INSTANCE_ID" \
  --items TypeName="AWS:Application",SchemaVersion="1.0",CaptureTime="$(date -u +%FT%TZ)",Content='[{"Name":"flask","Vendor":"PyPI","Version":"2.x"}]'
```

List inventory:

```bash
aws ssm list-inventory-entries --instance-id "$INSTANCE_ID" --type-name "AWS:InstanceInformation"
```

(For full fleet, use **SSM Inventory** in console + **Compliance** with associations/patch baselines.)

---

# 8) Bonus – OpsCenter incident from alarm

Create a simple CPU alarm → EventBridge rule → OpsItem.

**EventBridge rule (quick CLI skeleton):**

```bash
# Create a CW alarm (CPU > 70%)
aws cloudwatch put-metric-alarm \
  --alarm-name "HighCPU-SSM-Demo" \
  --metric-name CPUUtilization \
  --namespace AWS/EC2 \
  --statistic Average \
  --period 60 \
  --threshold 70 \
  --comparison-operator GreaterThanThreshold \
  --dimensions Name=InstanceId,Value=$INSTANCE_ID \
  --evaluation-periods 1

# EventBridge target to Systems Manager OpsItem
aws events put-rule --name "HighCPUToOpsItem" --event-pattern '{
  "source": ["aws.cloudwatch"],
  "detail-type": ["CloudWatch Alarm State Change"],
  "detail": { "alarmName": ["HighCPU-SSM-Demo"] }
}'

aws events put-targets \
  --rule "HighCPUToOpsItem" \
  --targets "Id"="1","Arn"="arn:aws:systems-manager:$(aws configure get region):$(aws sts get-caller-identity --query Account --output text):opsitem"
```

(You can also target an **SNS** to notify, and have a Lambda create OpsItem with `CreateOpsItem`.)

---

# 🔐 IAM snippets

**iam/ssm-automation-assume-role.json**

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Service": "ssm.amazonaws.com" },
    "Action": "sts:AssumeRole"
  }]
}
```

**iam/ssm-automation-passrole-policy.json**

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "AllowAutomationEc2",
    "Effect": "Allow",
    "Action": [
      "ec2:CreateImage",
      "ec2:CreateTags",
      "ssm:SendCommand"
    ],
    "Resource": "*"
  }]
}
```

*Create role & attach policy:*

```bash
aws iam create-role --role-name ssm-automation-exec \
  --assume-role-policy-document file://iam/ssm-automation-assume-role.json

aws iam put-role-policy --role-name ssm-automation-exec \
  --policy-name ssm-automation-inline \
  --policy-document file://iam/ssm-automation-passrole-policy.json
```

---

# 🔎 Useful verification

```bash
# Instance is managed?
aws ssm describe-instance-information --query "InstanceInformationList[?PingStatus=='Online']"

# Latest command results
aws ssm list-commands --max-results 5
aws ssm list-command-invocations --details --max-results 1

# Automation executions
aws ssm describe-automation-executions --max-results 5
```

---

# 🧹 Cleanup

```bash
# Remove SSM docs
for d in BootstrapLinuxApp PatchAndReboot AmiBackup; do
  aws ssm delete-document --name "$d" || true
done

# Delete maintenance window (if created)
MW_ID=$(aws ssm describe-maintenance-windows --query "WindowIdentities[?Name=='PatchWindow'].WindowId" --output text)
[ -n "$MW_ID" ] && aws ssm delete-maintenance-window --window-id $MW_ID || true

# Terraform destroy
terraform -chdir=terraform destroy -auto-approve

# IAM cleanup
aws iam delete-role-policy --role-name ssm-automation-exec --policy-name ssm-automation-inline || true
aws iam delete-role --role-name ssm-automation-exec || true
```

---

## 🧠 Trainer tips (for your workshops)

* Ask students to **rotate Parameter Store values** and show the app reflecting changes.
* Simulate drift: manually change `/opt/bootstrap_message.txt` and watch **State Manager** fix it.
* Schedule the **Maintenance Window** to run in the next few minutes for a live demo.
* Disable SSM Agent → show **non-compliant** inventory → re-enable to recover.
* Use **tags** on EC2 and target Run Command by `Key=tag:Env,Values=dev`.

---

If you’d like, I can drop this into a **GitHub-ready README** with the folder tree and files split out exactly as above.
