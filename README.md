# CoreApi-Asp.net-MVC-Sample
A sample app to demonstrate oAuth 2.0 for using Core APIs


GETTING STARTED:
Before beginning, it may be helpful to have a basic understanding of OAuth 2.0 concepts. To get started refer to Core API Documentation The purpose of this sample app is to perform three basic functions:
Complete the Authorization process and get tokens for communicating with Core
Demonstrate how to implement Sign in with Core using OpenId scope
Call Core Public API resources using access token
Revoke the Tokens
REQUIREMENTS:
In order to successfully run this app, you need the following:
A Core Developer Portal account
An app on Developer Portal and the associated Client_id, Client_Secret and Redirect_URI
Core sandbox/Production company
RUN YOUR APP:
All the configuration of this app is located in web.config. Your values must match exactly with what is listed in your app settings on Developer Portal To get started the developers need to make the required changes in web.config appsettings section. They can set the preferences like required endpoint urls, client app credentials and desired scopes for authentication. OAuth 2.0 needs core read write scopes for consuming CORE APIs. Additionally offline access scope will provide the refresh token while authenticating the client app. OpenId scope will provide user information like name, family name, email and will not work while connecting with Core.
