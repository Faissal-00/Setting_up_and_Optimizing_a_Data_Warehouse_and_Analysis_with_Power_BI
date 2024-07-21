# Project Context

In this project, I focused on optimizing the data management of an e-commerce platform. My approach involved several key steps:

## ETL with Talend
I utilized Talend to:
- **Extract Data**: Connect to various data sources (CSV, JSON) and retrieve the data.
- **Transform Data**: Clean and transform the data by handling missing values, converting data types, and applying business logic.
- **Load Data**: Load the transformed data into SQL Server. The ETL process was optimized using sub-jobs and best practices for error handling and performance.

## Schema Design
I implemented a star schema by:
- **Creating Dimension Tables**: Set up tables like `DateDimension`, `ProductDimension`, `CustomerDimension`, `SupplierDimension`, and `ShipperDimension`.
- **Creating Fact Tables**: Established `SalesFact` and `InventoryFact` tables and defined their relationships with the dimension tables.

## Data Marts
I developed physical data marts for:
- **Sales**: Including tables related to sales transactions.
- **Inventory**: Incorporating tables related to product inventory.

## Analytics with Power BI
I performed various analyses and created visualizations such as:
- **Sales Trends**
- **Top Products and Categories**
- **Customer Segmentation**
- **Impact of Discounts**
- **Supplier Performance**
- **Inventory Levels**
- **Stock Availability**
- **Supplier Evaluation**
- **Product Demand Forecasting**

I used visualizations like line charts, bar charts, pie charts, scatter plots, tables, and maps.

## Optimization
I implemented indexing and partitioning strategies to enhance query performance, with clear justifications for the optimizations.

## Validation
I wrote and executed SQL test cases to ensure that the data transformation logic was correctly applied.

## Authorization
I managed database users and roles, assigning appropriate permissions based on their responsibilities.

## GDPR Compliance
I:
- **Identified Sensitive Data**: Located and classified sensitive information in the system.
- **Implemented Protection Measures**: Applied encryption, pseudonymization, and access controls.
- **Ensured Rights Compliance**: Ensured mechanisms for data access, rectification, deletion, and portability.

This comprehensive approach ensured a well-structured data management system that supports insightful analytics while adhering to security and compliance standards.
