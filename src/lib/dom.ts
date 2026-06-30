type Child = Node | string

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  props: Partial<{ className: string; textContent: string; style: string; title: string }> = {},
  children: Child[] = [],
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag)
  if (props.className !== undefined) node.className = props.className
  if (props.textContent !== undefined) node.textContent = props.textContent
  if (props.style !== undefined) node.setAttribute('style', props.style)
  if (props.title !== undefined) node.title = props.title
  for (const c of children) node.append(c)
  return node
}

export function clear(node: Element): void {
  node.replaceChildren()
}

export function replace(node: Element, ...children: Child[]): void {
  node.replaceChildren(...children)
}
