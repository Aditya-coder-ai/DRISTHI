-- =====================================================================
-- MySQL Dump 10.13  Distrib 8.0.35, for Linux (x86_64)
-- Host: 10.0.1.25    Database: corp_finance_db
-- Server version: 8.0.35-0ubuntu0.22.04.1
-- Date: 2026-11-12 02:00:01
-- =====================================================================

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `customers`
--

DROP TABLE IF EXISTS `customers`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `customers` (
  `customer_id` int NOT NULL AUTO_INCREMENT,
  `company_name` varchar(100) NOT NULL,
  `contact_email` varchar(100) NOT NULL,
  `account_tier` enum('Enterprise','Strategic','Commercial') NOT NULL DEFAULT 'Commercial',
  `credit_limit` decimal(12,2) NOT NULL DEFAULT '50000.00',
  `tax_identifier` varchar(30) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`customer_id`),
  UNIQUE KEY `idx_cust_email` (`contact_email`)
) ENGINE=InnoDB AUTO_INCREMENT=2001 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `customers`
--

LOCK TABLES `customers` WRITE;
/*!40000 ALTER TABLE `customers` DISABLE KEYS */;
INSERT INTO `customers` VALUES 
(2001,'Apex Global Logistics','billing@apex-global.com','Enterprise',250000.00,'US-EIN-9481920','2023-01-15 10:20:00'),
(2002,'Vanguard Health Systems','finance@vanguard-health.org','Enterprise',500000.00,'US-EIN-8820194','2023-03-22 14:15:00'),
(2003,'Northstar Financial Tech','accounts@northstar-fin.com','Strategic',150000.00,'US-EIN-7729103','2023-06-05 09:30:00'),
(2004,'Quantum Energy Partners','ap@quantum-energy.net','Commercial',75000.00,'US-EIN-6629184','2024-02-18 11:45:00'),
(2005,'Horizon Media Networks','accounting@horizon-media.tv','Strategic',120000.00,'US-EIN-5520194','2024-08-30 16:00:00');
/*!40000 ALTER TABLE `customers` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `invoices`
--

DROP TABLE IF EXISTS `invoices`;
CREATE TABLE `invoices` (
  `invoice_id` int NOT NULL AUTO_INCREMENT,
  `customer_id` int NOT NULL,
  `invoice_number` varchar(50) NOT NULL,
  `amount` decimal(12,2) NOT NULL,
  `status` enum('PAID','PENDING','OVERDUE') NOT NULL DEFAULT 'PENDING',
  `due_date` date NOT NULL,
  PRIMARY KEY (`invoice_id`),
  KEY `fk_cust_inv` (`customer_id`),
  CONSTRAINT `fk_cust_inv` FOREIGN KEY (`customer_id`) REFERENCES `customers` (`customer_id`)
) ENGINE=InnoDB AUTO_INCREMENT=5001 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

LOCK TABLES `invoices` WRITE;
INSERT INTO `invoices` VALUES 
(5001,2001,'INV-2026-Q4-01',124500.00,'PAID','2026-10-31'),
(5002,2002,'INV-2026-Q4-02',289000.00,'PAID','2026-11-15'),
(5003,2003,'INV-2026-Q4-03',45000.00,'PENDING','2026-11-30');
UNLOCK TABLES;

-- Dump completed on 2026-11-12 02:00:05

