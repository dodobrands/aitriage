function show(bubble, post, completion) {
  bubble.textContent = completion.choices[0].message.content;
  post.innerHTML = marked.parse(post.body);
}
