import React from 'react'

export function highlightRego(line: string): React.ReactElement {
  const comments = /(#.*)$/

  // Check for comment first
  const commentMatch = line.match(comments)
  if (commentMatch && line.trimStart().startsWith('#')) {
    return <span className="text-gray-500 italic">{line}</span>
  }

  const parts: Array<{ text: string; className: string }> = []
  let lastIndex = 0

  // Build a combined regex for tokenization
  const combined = /("(?:[^"\\]|\\.)*")|(#.*)|\b(package|import|default|deny|allow|not|in|as|with|some|every|if|contains|else)\b|(:=|==|!=|>=|<=)|(\{|\}|\[|\])|(\b\d+\b)/g
  let match

  while ((match = combined.exec(line)) !== null) {
    // Add text before this match as plain
    if (match.index > lastIndex) {
      parts.push({ text: line.slice(lastIndex, match.index), className: 'text-green-400' })
    }

    if (match[1]) {
      // String literal
      parts.push({ text: match[0], className: 'text-amber-300' })
    } else if (match[2]) {
      // Comment
      parts.push({ text: match[0], className: 'text-gray-500 italic' })
    } else if (match[3]) {
      // Keyword
      parts.push({ text: match[0], className: 'text-purple-400 font-semibold' })
    } else if (match[4]) {
      // Operator
      parts.push({ text: match[0], className: 'text-cyan-400' })
    } else if (match[5]) {
      // Brackets
      parts.push({ text: match[0], className: 'text-yellow-300' })
    } else if (match[6]) {
      // Number
      parts.push({ text: match[0], className: 'text-orange-400' })
    } else {
      parts.push({ text: match[0], className: 'text-green-400' })
    }

    lastIndex = match.index + match[0].length
  }

  // Add remaining text
  if (lastIndex < line.length) {
    parts.push({ text: line.slice(lastIndex), className: 'text-green-400' })
  }

  if (parts.length === 0) {
    return <span className="text-green-400">{line}</span>
  }

  return (
    <>
      {parts.map((p, i) => (
        <span key={i} className={p.className}>{p.text}</span>
      ))}
    </>
  )
}
