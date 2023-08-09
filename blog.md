---
layout: default
---


<h1>Blog Posts</h1>

<ul>
  {% for post in site.posts %}
    <li>
      <h2><a href="{{ post.url }}">{{ post.title }}</a></h2>
      <p>{{ post.excerpt | strip_html }}</p>
    </li>
  {% endfor %}
</ul>

[back](./about)