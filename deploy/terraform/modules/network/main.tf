locals {
  resource_name = "${var.project_name}-${var.environment}-network"

  common_tags = merge(var.tags, {
    application_id = var.project_name
    environment    = var.environment
    cost_center    = "engineering"
    owner          = "platform-team"
  })
}

# ─── GCP: VPC + Custom Subnets + Cloud NAT + Firewall Rules ────────────────

resource "google_compute_network" "this" {
  count                   = var.cloud_provider == "gcp" ? 1 : 0
  name                    = local.resource_name
  auto_create_subnetworks = false
  routing_mode            = "REGIONAL"
}

resource "google_compute_subnetwork" "private" {
  count                    = var.cloud_provider == "gcp" ? var.subnet_count : 0
  name                     = "${local.resource_name}-private-${count.index}"
  ip_cidr_range            = cidrsubnet(var.cidr_block, 8, count.index)
  region                   = var.region
  network                  = google_compute_network.this[0].id
  private_ip_google_access = true

  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = var.enable_flow_logs ? 0.5 : 0
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

resource "google_compute_subnetwork" "public" {
  count         = var.cloud_provider == "gcp" ? var.subnet_count : 0
  name          = "${local.resource_name}-public-${count.index}"
  ip_cidr_range = cidrsubnet(var.cidr_block, 8, count.index + var.subnet_count)
  region        = var.region
  network       = google_compute_network.this[0].id
}

resource "google_compute_router" "this" {
  count   = var.cloud_provider == "gcp" && var.enable_nat ? 1 : 0
  name    = "${local.resource_name}-router"
  region  = var.region
  network = google_compute_network.this[0].id
}

resource "google_compute_router_nat" "this" {
  count                              = var.cloud_provider == "gcp" && var.enable_nat ? 1 : 0
  name                               = "${local.resource_name}-nat"
  router                             = google_compute_router.this[0].name
  region                             = var.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"

  log_config {
    enable = var.enable_flow_logs
    filter = "ERRORS_ONLY"
  }
}

resource "google_compute_firewall" "allow_internal" {
  count   = var.cloud_provider == "gcp" ? 1 : 0
  name    = "${local.resource_name}-allow-internal"
  network = google_compute_network.this[0].name

  allow {
    protocol = "tcp"
    ports    = ["0-65535"]
  }

  allow {
    protocol = "udp"
    ports    = ["0-65535"]
  }

  allow {
    protocol = "icmp"
  }

  source_ranges = [var.cidr_block]
}

resource "google_compute_firewall" "deny_all_ingress" {
  count    = var.cloud_provider == "gcp" ? 1 : 0
  name     = "${local.resource_name}-deny-all-ingress"
  network  = google_compute_network.this[0].name
  priority = 65534

  deny {
    protocol = "all"
  }

  source_ranges = ["0.0.0.0/0"]
}

# ─── AWS: VPC + Public/Private Subnets + NAT Gateway + Flow Logs ───────────

resource "aws_vpc" "this" {
  count                = var.cloud_provider == "aws" ? 1 : 0
  cidr_block           = var.cidr_block
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = merge(local.common_tags, {
    Name = local.resource_name
  })
}

resource "aws_subnet" "private" {
  count             = var.cloud_provider == "aws" ? var.subnet_count : 0
  vpc_id            = aws_vpc.this[0].id
  cidr_block        = cidrsubnet(var.cidr_block, 8, count.index)
  availability_zone = data.aws_availability_zones.available[0].names[count.index % length(data.aws_availability_zones.available[0].names)]

  tags = merge(local.common_tags, {
    Name = "${local.resource_name}-private-${count.index}"
    Tier = "private"
  })
}

resource "aws_subnet" "public" {
  count                   = var.cloud_provider == "aws" ? var.subnet_count : 0
  vpc_id                  = aws_vpc.this[0].id
  cidr_block              = cidrsubnet(var.cidr_block, 8, count.index + var.subnet_count)
  availability_zone       = data.aws_availability_zones.available[0].names[count.index % length(data.aws_availability_zones.available[0].names)]
  map_public_ip_on_launch = false  # Policy: no auto-assign public IPs

  tags = merge(local.common_tags, {
    Name = "${local.resource_name}-public-${count.index}"
    Tier = "public"
  })
}

data "aws_availability_zones" "available" {
  count = var.cloud_provider == "aws" ? 1 : 0
  state = "available"
}

resource "aws_internet_gateway" "this" {
  count  = var.cloud_provider == "aws" ? 1 : 0
  vpc_id = aws_vpc.this[0].id

  tags = merge(local.common_tags, {
    Name = "${local.resource_name}-igw"
  })
}

resource "aws_eip" "nat" {
  count  = var.cloud_provider == "aws" && var.enable_nat ? 1 : 0
  domain = "vpc"

  tags = merge(local.common_tags, {
    Name = "${local.resource_name}-nat-eip"
  })
}

resource "aws_nat_gateway" "this" {
  count         = var.cloud_provider == "aws" && var.enable_nat ? 1 : 0
  allocation_id = aws_eip.nat[0].id
  subnet_id     = aws_subnet.public[0].id

  tags = merge(local.common_tags, {
    Name = "${local.resource_name}-nat"
  })

  depends_on = [aws_internet_gateway.this]
}

resource "aws_route_table" "private" {
  count  = var.cloud_provider == "aws" ? 1 : 0
  vpc_id = aws_vpc.this[0].id

  tags = merge(local.common_tags, {
    Name = "${local.resource_name}-private-rt"
  })
}

resource "aws_route" "private_nat" {
  count                  = var.cloud_provider == "aws" && var.enable_nat ? 1 : 0
  route_table_id         = aws_route_table.private[0].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.this[0].id
}

resource "aws_route_table_association" "private" {
  count          = var.cloud_provider == "aws" ? var.subnet_count : 0
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[0].id
}

resource "aws_route_table" "public" {
  count  = var.cloud_provider == "aws" ? 1 : 0
  vpc_id = aws_vpc.this[0].id

  tags = merge(local.common_tags, {
    Name = "${local.resource_name}-public-rt"
  })
}

resource "aws_route" "public_igw" {
  count                  = var.cloud_provider == "aws" ? 1 : 0
  route_table_id         = aws_route_table.public[0].id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this[0].id
}

resource "aws_route_table_association" "public" {
  count          = var.cloud_provider == "aws" ? var.subnet_count : 0
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public[0].id
}

resource "aws_flow_log" "this" {
  count                = var.cloud_provider == "aws" && var.enable_flow_logs ? 1 : 0
  vpc_id               = aws_vpc.this[0].id
  traffic_type         = "ALL"
  log_destination_type = "cloud-watch-logs"
  log_destination      = aws_cloudwatch_log_group.flow_logs[0].arn
  iam_role_arn         = aws_iam_role.flow_logs[0].arn

  tags = local.common_tags
}

resource "aws_cloudwatch_log_group" "flow_logs" {
  count             = var.cloud_provider == "aws" && var.enable_flow_logs ? 1 : 0
  name              = "/vpc/${local.resource_name}/flow-logs"
  retention_in_days = 30

  tags = local.common_tags
}

resource "aws_iam_role" "flow_logs" {
  count = var.cloud_provider == "aws" && var.enable_flow_logs ? 1 : 0
  name  = "${local.resource_name}-flow-logs-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "vpc-flow-logs.amazonaws.com"
      }
    }]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy" "flow_logs" {
  count = var.cloud_provider == "aws" && var.enable_flow_logs ? 1 : 0
  name  = "${local.resource_name}-flow-logs-policy"
  role  = aws_iam_role.flow_logs[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ]
      Effect   = "Allow"
      Resource = "*"
    }]
  })
}

# ─── Azure: VNet + Subnets + NSG + Service Endpoints ───────────────────────

resource "azurerm_virtual_network" "this" {
  count               = var.cloud_provider == "azure" ? 1 : 0
  name                = local.resource_name
  address_space       = [var.cidr_block]
  location            = var.region
  resource_group_name = var.azure_resource_group

  tags = local.common_tags
}

resource "azurerm_subnet" "private" {
  count                = var.cloud_provider == "azure" ? var.subnet_count : 0
  name                 = "${local.resource_name}-private-${count.index}"
  resource_group_name  = var.azure_resource_group
  virtual_network_name = azurerm_virtual_network.this[0].name
  address_prefixes     = [cidrsubnet(var.cidr_block, 8, count.index)]

  service_endpoints = [
    "Microsoft.Sql",
    "Microsoft.Storage",
    "Microsoft.KeyVault",
  ]
}

resource "azurerm_subnet" "public" {
  count                = var.cloud_provider == "azure" ? var.subnet_count : 0
  name                 = "${local.resource_name}-public-${count.index}"
  resource_group_name  = var.azure_resource_group
  virtual_network_name = azurerm_virtual_network.this[0].name
  address_prefixes     = [cidrsubnet(var.cidr_block, 8, count.index + var.subnet_count)]
}

resource "azurerm_network_security_group" "private" {
  count               = var.cloud_provider == "azure" ? 1 : 0
  name                = "${local.resource_name}-private-nsg"
  location            = var.region
  resource_group_name = var.azure_resource_group

  security_rule {
    name                       = "AllowVNetInbound"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "VirtualNetwork"
    destination_address_prefix = "VirtualNetwork"
  }

  security_rule {
    name                       = "DenyAllInbound"
    priority                   = 4096
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  tags = local.common_tags
}

resource "azurerm_subnet_network_security_group_association" "private" {
  count                     = var.cloud_provider == "azure" ? var.subnet_count : 0
  subnet_id                 = azurerm_subnet.private[count.index].id
  network_security_group_id = azurerm_network_security_group.private[0].id
}

resource "azurerm_public_ip" "nat" {
  count               = var.cloud_provider == "azure" && var.enable_nat ? 1 : 0
  name                = "${local.resource_name}-nat-pip"
  location            = var.region
  resource_group_name = var.azure_resource_group
  allocation_method   = "Static"
  sku                 = "Standard"

  tags = local.common_tags
}

resource "azurerm_nat_gateway" "this" {
  count               = var.cloud_provider == "azure" && var.enable_nat ? 1 : 0
  name                = "${local.resource_name}-nat"
  location            = var.region
  resource_group_name = var.azure_resource_group
  sku_name            = "Standard"

  tags = local.common_tags
}

resource "azurerm_nat_gateway_public_ip_association" "this" {
  count                = var.cloud_provider == "azure" && var.enable_nat ? 1 : 0
  nat_gateway_id       = azurerm_nat_gateway.this[0].id
  public_ip_address_id = azurerm_public_ip.nat[0].id
}

resource "azurerm_subnet_nat_gateway_association" "private" {
  count          = var.cloud_provider == "azure" && var.enable_nat ? var.subnet_count : 0
  subnet_id      = azurerm_subnet.private[count.index].id
  nat_gateway_id = azurerm_nat_gateway.this[0].id
}
