# CoreApi-Asp.net-MVC-Sample
A sample app demonstrating oAuth 2.0 using Core APIs


## Getting Started:

Before beginning, it might be helpful to have a basic understanding of OAuth 2.0 and related concepts. To know more about oAuth 2.0 refer to [Core API Documentation](https://api-explorer.bqecore.com/docs/authentication-authorization). The purpose of this sample app is to perform three basic functions:
  * Complete the authorization process and receive tokens for communicating with Core
  * Demonstrate how to implement sign in with Core using OpenId scope
  * Call Core Public API resources using access token
  * Revoke the tokens
  
### Requirements:

To successfully run this app, you need the following:
  * A Core [Developer Portal](https://api-developer.bqecore.com/webapp) account
  * An app on Developer Portal and the associated Client_id, Client_Secret and Redirect_URI
  * Core Sandbox/Production company
  
### Run Your Application:

All the configuration of this app is located in web.config. Your values must match exactly with what is listed in your app settings on Developer Portal. To get started the developers need to make the required changes in web.config appsettings section. They can set the preferences like required endpoint urls, client app credentials and desired scopes for authentication. oAuth 2.0 needs core read write scopes for consuming Core APIs. Additionally, offline access scope will provide the refresh token while authenticating the client app. OpenId scope will provide user information like name, family name, email and will not work while connecting with Core.

### What is supported?

  1. Authorization
  2. Authentication
  3. Account - Add and Create
  
### Querying

We allow the following simple filters on different endpoints:

  * Fields - To specify only those model properties which you want in the response body
  * Where - To specify only those records that match the query expression
  * Order By - To specify by which field you want to order the item list
  * Page - To specify the page number and number of records on each page
  
Core API allows operators to manipulate individual data items and return a result set. To know more go to [Core operators](https://api-explorer.bqecore.com/docs/filtering#filter-operators)
