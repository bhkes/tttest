// 테라폼블록
terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
      version = "5.49.0"
    }
  }
}

// 프로바이더 블록
provider "aws" {
  region = "ap-northeast-2"
}

//리소스 블록
resource "aws_vpc" "kim_vpc" {
  cidr_block = "10.1.0.0/16"

  tags = {
      Name = "kim-vpc"
  }
}

//인터넷 게이트 웨이 생성
resource "aws_internet_gateway" "kim_igw" {
  vpc_id = aws_vpc.kim_vpc.id

  tags = {
    Name = "kim-igw"
  }
}

//igw att
//igw att는 테라폼으로 igw 생성시 기본적으로 igw가 vpc에 자동 연결된 상태로
//생성 되기 때문에 주석 처리하였음.
# resource "aws_internet_gateway_attachment" "kim_vpc" {
#   internet_gateway_id = aws_internet_gateway.kim_vpc.id
#   vpc_id              = aws_vpc.kim_vpc.id
# }

# resource "aws_vpc" "kim_vpc" {
#   cidr_block = "10.1.0.0/16"

#   tags = {
#       Name = "kim-vpc"
#   }
# }
# resource "aws_internet_gateway" "kim_vpc" {}
//igw att end

// 퍼블릭 서브넷 생성
resource "aws_subnet" "kim_pub_sn1" {
  vpc_id     = aws_vpc.kim_vpc.id
  cidr_block = "10.1.1.0/24"
  availability_zone = "ap-northeast-2a"

  tags = {
    Name = "kim-public-sn1"
  }
}

resource "aws_subnet" "kim_pub_sn2" {
  vpc_id     = aws_vpc.kim_vpc.id
  cidr_block = "10.1.2.0/24"
  availability_zone = "ap-northeast-2c"

  tags = {
    Name = "kim-public-sn2"
  }
}

// 프라이빗 서브넷 생성
resource "aws_subnet" "kim_pri_sn3" {
  vpc_id     = aws_vpc.kim_vpc.id
  cidr_block = "10.1.3.0/24"
  availability_zone = "ap-northeast-2a"

  tags = {
    Name = "kim-private-sn3"
  }
}

resource "aws_subnet" "kim_pri_sn4" {
  vpc_id     = aws_vpc.kim_vpc.id
  cidr_block = "10.1.4.0/24"
  availability_zone = "ap-northeast-2c"

  tags = {
    Name = "kim-private-sn4"
  }
}

//퍼블릭 라우팅테이블 생성
resource "aws_route_table" "kim_pub_rt1" {
  vpc_id = aws_vpc.kim_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.kim_igw.id
  }

  tags = {
    Name = "kim-public-rt1"
  }
}

//퍼블릭 라우팅테이블에 서브넷 연결
resource "aws_route_table_association" "kim_pub_rt_ass1" {
  subnet_id      = aws_subnet.kim_pub_sn1.id
  route_table_id = aws_route_table.kim_pub_rt1.id
}

resource "aws_route_table_association" "kim_pub_rt_ass2" {
  subnet_id      = aws_subnet.kim_pub_sn2.id
  route_table_id = aws_route_table.kim_pub_rt1.id
}

// 프라이빗 라우팅테이블 생성
resource "aws_route_table" "kim_pri_rt3" {
  vpc_id = aws_vpc.kim_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    network_interface_id   = aws_instance.kim_NAT.primary_network_interface_id
   // instance_id = aws_instance.kim_NAT.id    
  }

  depends_on = [aws_instance.kim_NAT]

  tags = {
    Name = "kim-private-rt3"
  }
}

# # 프라이빗 라우팅 테이블에 NAT 인스턴스를 연결
# resource "aws_route" "private_nat_route" {
#   route_table_id            = aws_route_table.kim_pri_rt3.id  # 프라이빗 라우팅 테이블 ID 입력
#   destination_cidr_block    = "0.0.0.0/0"                  # 외부 트래픽으로의 대상 CIDR 블록
#   instance_id               = aws_instance.kim_NAT.id # NAT 인스턴스 ID 입력
# }

// 프라이빗 라우팅테이블에 서브넷 연결
resource "aws_route_table_association" "kim_pri_rt_ass1" {
  subnet_id      = aws_subnet.kim_pri_sn3.id
  route_table_id = aws_route_table.kim_pri_rt3.id
}

resource "aws_route_table_association" "kim_pri_rt_ass2" {
  subnet_id      = aws_subnet.kim_pri_sn4.id
  route_table_id = aws_route_table.kim_pri_rt3.id
}

// NAT instance 생성
resource "aws_instance" "kim_NAT" {
  ami                         = "ami-071a42ffa63391c66"
  instance_type               = "t2.micro"
  subnet_id                   = aws_subnet.kim_pub_sn1.id
  vpc_security_group_ids      = [aws_security_group.kim_NAT_SG.id]
  associate_public_ip_address = true
  key_name                    = "kim-key"
  private_ip                  = "10.1.1.100"
  source_dest_check           = false
  user_data                   = <<-EOT
  #!/bin/bash
  echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
  yum install -y iptables-services
  systemctl start iptables.service
  systemctl enable iptables.service
  iptables -F
  iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
  service iptables save
  EOT
 
 //보안그룹에 대한 depends_on 은 일단 생략해보고 문제 생기면 그때 해볼 생각0528
  tags = {
    Name = "kim-NAT"
  }
}


// ami를 불러오는 data블록 생성. 추후 구현에 사용할 예정
# data "aws_ami" "ubuntu" {
#   most_recent = true

#   filter {
#     name   = "name"
#     values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
#   }

#   filter {
#     name   = "virtualization-type"
#     values = ["hvm"]
#   }

#   owners = ["099720109477"] # Canonical
# }

# resource "aws_instance" "web" {
#   ami           = data.aws_ami.ubuntu.id
#   instance_type = "t3.micro"

#   tags = {
#     Name = "HelloWorld"
#   }
# }

# # 데이터 블록
# data "aws_ami" "web_ami" {
#   most_recent = true
#   filter {
#     name   = "name"
#     values = ["amzn2-ami-kernel-5.10-hvm-2.0.20240503.0-x86_64-gp2"]
#   }
#   filter {
#     name   = "virtualization-type"
#     values = ["hvm"]
#   }
#   owners = ["137112412989"]
# }

// 보안그룹(NAT Instance전용) 생성
resource "aws_security_group" "kim_NAT_SG" {
  name        = "kim-NAT-SG"
  description = "kim-NAT-SG"
  vpc_id      = aws_vpc.kim_vpc.id

  tags = {
    Name = "kim-NAT-SG"
  }
}

// 보안그룹 인바운드 규칙
resource "aws_vpc_security_group_ingress_rule" "kim_NAT_SG_ingress_ssh" {
  security_group_id = aws_security_group.kim_NAT_SG.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 22
  ip_protocol       = "tcp"
  to_port           = 22
  # 관리자가 어디서든 bastion host에 접속할 수 있게 편의상 모든 경로에서 ssh 허용
}

resource "aws_vpc_security_group_ingress_rule" "kim_NAT_SG_ingress_icmp" {
  security_group_id = aws_security_group.kim_NAT_SG.id
  cidr_ipv4         = "10.1.0.0/16"
  from_port         = -1
  ip_protocol       = "ICMP"
  to_port           = -1
  # vpc내에서 ping 테스트를 위해 10.1.0.0/16(=vpc)에서 오는 모든ICMP 허용
}

resource "aws_vpc_security_group_ingress_rule" "kim_NAT_SG_ingress_all_3" {
  security_group_id = aws_security_group.kim_NAT_SG.id
  cidr_ipv4         = "10.1.3.0/24"
  ip_protocol       = -1
  # nat instance로서 기능하기 위해 10.1.3.0/24 에서 오는 모든 트래픽 허용
}

resource "aws_vpc_security_group_ingress_rule" "kim_NAT_SG_ingress_all_4" {
  security_group_id = aws_security_group.kim_NAT_SG.id
  cidr_ipv4         = "10.1.4.0/24"
  ip_protocol       = -1
  # nat instance로서 기능하기 위해 10.1.4.0/24 에서 오는 모든 트래픽 허용
}
// 보안그룹 아웃바운드 규칙
resource "aws_vpc_security_group_egress_rule" "kim_NAT_SG_egress" {
  security_group_id = aws_security_group.kim_NAT_SG.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1" # semantically equivalent to all ports
}



// 보안그룹(Web전용) 생성
resource "aws_security_group" "kim_Web_SG" {
  name        = "kim-Web-SG"
  description = "kim-Web-SG"
  vpc_id      = aws_vpc.kim_vpc.id

  tags = {
    Name = "kim-Web-SG"
  }
}

// 보안그룹 인바운드 규칙
resource "aws_vpc_security_group_ingress_rule" "kim_Web_SG_ingress_ssh" {
  security_group_id = aws_security_group.kim_Web_SG.id
  cidr_ipv4         = "10.1.1.100/32"
  from_port         = 22
  ip_protocol       = "tcp"
  to_port           = 22
  # 관리자가 bastion host를 통해 Web서버를 관리할 수 있게 ssh 허용
}

resource "aws_vpc_security_group_ingress_rule" "kim_Web_SG_ingress_icmp" {
  security_group_id = aws_security_group.kim_Web_SG.id
  cidr_ipv4         = "10.1.0.0/16"
  from_port         = -1
  ip_protocol       = "ICMP"
  to_port           = -1
  # vpc내에서 ping 테스트를 위해 10.1.0.0/16(=vpc)에서 오는 모든ICMP 허용
}

resource "aws_vpc_security_group_ingress_rule" "kim_Web_SG_ingress_http" {
  security_group_id = aws_security_group.kim_Web_SG.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 80
  ip_protocol       = "tcp"
  to_port           = 80
  # web서버로서 기능하기 위해 모든 http 허용
}

resource "aws_vpc_security_group_ingress_rule" "kim_Web_SG_ingress_https" {
  security_group_id = aws_security_group.kim_Web_SG.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 443
  ip_protocol       = "tcp"
  to_port           = 443
  # web서버로서 기능하기 위해 모든 https 허용
}

// 보안그룹 아웃바운드 규칙
resource "aws_vpc_security_group_egress_rule" "kim_Web_SG_egress" {
  security_group_id = aws_security_group.kim_Web_SG.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1" # semantically equivalent to all ports
}



// 보안그룹(ALB전용) 생성
resource "aws_security_group" "kim_ALB_SG" {
  name        = "kim-ALB-SG"
  description = "kim-ALB-SG"
  vpc_id      = aws_vpc.kim_vpc.id

  tags = {
    Name = "kim-ALB-SG"
  }
}

resource "aws_vpc_security_group_ingress_rule" "kim_ALB_SG_ingress_http" {
  security_group_id = aws_security_group.kim_ALB_SG.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 80
  ip_protocol       = "tcp"
  to_port           = 80
  # web서버의 부하분산을 위한 로드밸런서의 트래픽에 대해 모든 http 허용
}

resource "aws_vpc_security_group_ingress_rule" "kim_ALB_SG_ingress_https" {
  security_group_id = aws_security_group.kim_ALB_SG.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 443
  ip_protocol       = "tcp"
  to_port           = 443
  # web서버의 부하분산을 위한 로드밸런서의 트래픽에 대해 모든 https 허용
}

// 보안그룹 아웃바운드 규칙
resource "aws_vpc_security_group_egress_rule" "kim_ALB_SG_egress" {
  security_group_id = aws_security_group.kim_ALB_SG.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1" # semantically equivalent to all ports
}

// EC2 인스턴스 생성(웹서버 샘플)
resource "aws_instance" "web_sample" {
  ami                         = "ami-071a42ffa63391c66"
  instance_type               = "t2.micro"
  associate_public_ip_address = true
  subnet_id                   = aws_subnet.kim_pub_sn1.id
  vpc_security_group_ids      = [aws_security_group.kim_Web_SG.id]
  //ami이기 때문에 vpc,서브넷 모두 주석처리해도되지않나 싶음. 추후 실험예정0604
  //depends_on = [aws_route_table.kim_pri_rt3]
  user_data                   = <<-EOT
  #!/bin/bash
  echo "p@ssw0rd" | passwd --stdin root
  sed -i "s/^#PermitRootLogin yes/PermitRootLogin yes/g" /etc/ssh/sshd_config
  sed -i "s/^PasswordAuthentication no/PasswordAuthentication yes/g" /etc/ssh/sshd_config
  systemctl restart sshd
  yum install -y httpd php mysql php-mysql
  systemctl start httpd
  systemctl enable httpd
  wget -O /var/www/html/rds.tar.gz https://github.com/bhkes/tttest/raw/main/aws/rds.tar.gz
  cd /var/www/html/
  tar xfz rds.tar.gz
  chown apache.root /var/www/html/rds.conf.php
  yum -y update
  EOT
  // /var/www/html/rds.tar.gz가 경로가 맞는지 확인필요 605
  //근데 다시생각해보니 왜 인스턴스가 먹통이됐는지 알 거 같음.
  //최상위 폴더에 있는 모든 파일을 /var/www/html에 옮기려고 하니까 오류가 발생한듯
  //이제 왜 이렇게 되는지 알았으니까 다시 wget이하 코드를 
  // 사용자 데이터에 넣어봐도 될듯 0605
  tags = {
    Name = "web-sample"
  }
}

#   yum install -y httpd
#   echo "<h1><font color=red>Terraform Web Server1</font></h1>" > /var/www/html/index.html
#   systemctl start httpd

# yum install -y httpd php mysql php-mysql
# systemctl start httpd
# systemctl enable httpd
# wget https://github.com/bhkes/tttest/raw/main/aws/rds.tar.gz
# tar xfz rds.tar.gz
# mv ./* /var/www/html/
# chown apache.root /var/www/html/rds.conf.php
# yum -y update

// AMI 생성
resource "aws_ami_from_instance" "web_sample_ami" {
  name                      = "web-sample"
  source_instance_id        = aws_instance.web_sample.id
}

// 시작템플릿 생성
resource "aws_launch_template" "lt_web_server" {
  name = "web-server"
  image_id = aws_ami_from_instance.web_sample_ami.id
  instance_type = "t2.micro"
//  key_name  = 시작템플릿에 포함하지 않음 인데 해당 값으로 뭘넣어야할지 안보임
//  subnet_id = 시작템플릿에 포함하지 않음 인데 해당 값으로 뭘넣어야할지 안보임
  vpc_security_group_ids = [aws_security_group.kim_Web_SG.id]

  user_data = base64encode(<<EOF
#!/bin/bash
echo "p@ssw0rd" | passwd --stdin root
sed -i "s/^#PermitRootLogin yes/PermitRootLogin yes/g" /etc/ssh/sshd_config
sed -i "s/^PasswordAuthentication no/PasswordAuthentication yes/g" /etc/ssh/sshd_config
systemctl restart sshd
EOF
)
  # user_data                   = <<-EOT
  # #!/bin/bash
  # echo "p@ssw0rd" | passwd --stdin root
  # sed -i "s/^#PermitRootLogin yes/PermitRootLogin yes/g" /etc/ssh/sshd_config
  # sed -i "s/^PasswordAuthentication no/PasswordAuthentication yes/g" /etc/ssh/sshd_config
  # systemctl restart sshd
  # EOT
}

// 대상 그룹 생성
resource "aws_lb_target_group" "kim_sg" {
  name     = "kim-sg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.kim_vpc.id
}

// ALB 생성
resource "aws_lb" "kim_alb" {
  load_balancer_type = "application"
  name               = "kim-alb"

//  vpc_id             = aws_vpc.kim_vpc.id
// aws console에서 alb생성시 vpc값을 지정해 줘야 하는데
// terraform에서는 vpc 인수가 존재 하지 않음
// 서브넷에 vpc 정보가 내재되어 있다보니 vpc 인수가 없는 걸지도?

//  internal           = false (default값이 false이므로 생략)
// 내부가 아닌 '인터넷 경계'에 로드밸런서 생성하는 인수
  subnet_mapping {
    subnet_id     = aws_subnet.kim_pub_sn1.id
  }
  subnet_mapping {
    subnet_id     = aws_subnet.kim_pub_sn2.id
  }
  security_groups    = [aws_security_group.kim_ALB_SG.id]
}

// alb 리스너 및 라우팅 생성
resource "aws_lb_listener" "kim_alb_listener" {
  load_balancer_arn = aws_lb.kim_alb.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.kim_sg.arn
  }
}

// 오토스케일링 그룹 생성
resource "aws_autoscaling_group" "kim_asg" {
  name                      = "kim-asg"

  launch_template {
    id      = aws_launch_template.lt_web_server.id
    version = "$Default"
  }

  vpc_zone_identifier       = [aws_subnet.kim_pri_sn3.id, aws_subnet.kim_pri_sn4.id]
  target_group_arns         = [aws_lb_target_group.kim_sg.arn]
// target_group_arns가 load_balancers 인수 역할을 대신한다고 함

  desired_capacity          = 2
  max_size                  = 4
  min_size                  = 2

}

// 오토스케일링 대상 추적 크기 조정 정책 생성
resource "aws_autoscaling_policy" "kim_asg_policy" {
  autoscaling_group_name = aws_autoscaling_group.kim_asg.name
  name                   = "Target Tracking Policy"
  policy_type            = "TargetTrackingScaling"  
  
  target_tracking_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ASGAverageCPUUtilization"
    }
    target_value           = 50.0
  }
  estimated_instance_warmup = 120
// 인스턴스 워밍업 시간이 기본적으로 300초로 설정되어 있어서 
// 빠른 확인을 위해 120초로 설정
// cooldown ?
}

# resource "aws_route53_zone" "alb_hosted_zone" {
#   name = "xyz503.xyz"
# }

# resource "aws_route53_record" "alb_dns_mapping" {
#   zone_id = aws_route53_zone.alb_hosted_zone.zone_id
#   name    = "project.xyz503.xyz"
#   type    = "A"

resource "aws_route53_record" "alb_dns_mapping" {
  zone_id = "Z076485138MXL0H0GNVZD"
  name    = "project.xyz503.xyz"
  type    = "A"

  alias {
    name                   = aws_lb.kim_alb.dns_name
    //name = 로드밸런서의 dns 주소?
    zone_id                = aws_lb.kim_alb.zone_id
    // zone_id = 로드밸런서의 호스팅 영역?
    evaluate_target_health = true
  }
}