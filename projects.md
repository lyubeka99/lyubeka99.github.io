---
layout: default
---

<h1>Projects</h1>

<ul>
  {% for post in site.projects %}
    <li class="project">
      <div class="project-image">
        <img src="{{ post.image }}" alt="{{ post.title }}">
      </div>
      <div class="project-summary">
        <h2><a href="{{ post.url }}">{{ post.title }}</a></h2>
        <p>{{ post.excerpt | strip_html }}</p>
      </div>
    </li>
  {% endfor %}
</ul>

[back](./about)