function show(bubble, completion) {
  // ruleid: LLM-OUTPUT-HTML
  bubble.innerHTML = marked.parse(completion.choices[0].message.content);
}
