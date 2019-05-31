# ASP.NET MVC Sample App
A sample app demonstrating OAuth 2.0 using Core APIs


## Getting Started:

Before getting started, it might be helpful to have a basic understanding of OAuth 2.0 and related concepts. To know more about OAuth 2.0 refer to [Core API Documentation](https://api-explorer.bqecore.com/docs/authentication-authorization). The purpose of this sample app is to perform three basic functions:
  * Complete the authorization process and receive tokens for communicating with Core
  * Demonstrate how to implement sign in with Core using OpenId scopes
  * Call Core Public API resources using access token
  * Revoke the tokens
  
### Requirements:

To successfully run this app, you need the following:
  * A Core [developer](https://api-developer.bqecore.com/webapp) account
  * An app on Developer Portal and the associated client_id, client_secret and redirect_uri
  * Core Sandbox/Production company
  
### Run Your Application:

All the configuration of this app is located in web.config. Its values must match exactly with what is listed in the app settings on the developer portal. To get started, you need to make the required changes in web.config appsettings section. You can set the preferences like required endpoint urls, client app credentials and desired scopes for authentication. OAuth 2.0 needs read:core or readwrite:core scopes for consuming Core APIs. Additionally, offline_access scope will provide the refresh token while authenticating the client app. openid and profile scopes will provide user information like name, family name, email and will not work while connecting with Core.

### What is supported?

  1. Authorization
  2. Authentication
  3. Account - Add and Create
  
### Querying

We allow the following simple filters on different endpoints:

  * fields - To specify only those model properties which you want in the response body
  * where - To specify only those records that match the query expression
  * orderBy - To specify by which field you want to order the item list
  * page - To specify the page number and number of records on each page
  
Core API allows operators to manipulate individual data items and return a result set. To know more go to [Core operators](https://api-explorer.bqecore.com/docs/filtering#filter-operators)
