__[Home](help.md) | TagHelpers | [Geo](Geo.md) | [FireWall Rules](Rules.md)__

## Tag Helpers
The firewall contains several Tag helpers that allow you to fine tune your rozor the content of your .cshtml pages.

### Getting started
Open your  __viewimports.cshtml page in the root of your Views folder and add the following statement
```C#
@using Walter.Web.FireWall.TagHelpers;
@addTagHelper *, Walter.Web.FireWall.TagHelpers 
```	

Please note that Geo tag helpers are documented [a here](Geo.md)

After doing that you will be able to use following tags in your html razor pages
### User & Roles

#### Role Management
You can limit access to resources based on a users role, if the user does not have this role, or has not authenticated him self the html fragment will not be rendered and the user & browser are non the wiser.
```html
<Role app-user="RoleName">
<div>...</div>
<script src="~js/MembersOnly/__hard_to_guess_rolename__.js"></script>
</role>
```	

If enable the firewall rule _"Guessing"_ for a given folder say _~js/MembersOnly/*.js_ that you can state that anyone requesting 
content will be blocked when guessing/ fishing occurs for that specific folder making that folder more, or less restrictive than the default implementation.
for more information on this look at [a  firewall rules](rules.md) for more information on this topic.

#### Human verified only content
 The *firewall-users* attribute will render the content only if we have identified that a given request is a user and not a bot. the tag is available in  ```<div>``` , ```<section>```, ```<input>```, ```<script>``` tags as demonstrated bellow. There are limitations to this functionality being that will cause us to sometimes not be a hundred percent sure that the request if from a user, if in doubt we will show the content
```html

<div firewall-users class="container">
<img src="copyrighted.png" firewall-users class="animation"/>
...
</div>

<script firewall-users src="~js/HumansOnly/__hard_to_guess_humans-only__.js"></script>

```	


#### Bot verified content
Sometimes you would like to render content based on a given bot/ search engine. the *firewall-bot* allows you to do just that.
there are 2 ways to do this, you can give it a value and then only the identified bot or bot group will be allowed to pass or not specify anything and then all bots will get the same content.
This feature is particular help full when used in combination with the user's attribute when you would like to render micro data type of content or hide images from search engines. 

The below sample will load script tag only if we are sure the visiting bot is google
  
```html

<script firewall-bot="Google" type="application/ld+json>
{
"@context":"htt://schema.org",
 "@type": "Product",
  "name": "Executive Anvil",
  "image": [
    "https://example.com/photos/1x1/photo.jpg",
    "https://example.com/photos/4x3/photo.jpg",
    "https://example.com/photos/16x9/photo.jpg"
   ],
...
}
</script>

```	