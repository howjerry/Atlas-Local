// dangerouslySetInnerHTML: should NOT trigger the rule
// 使用安全的文字渲染方式

import React from "react";

function SafeComponent({ textContent }: { textContent: string }) {
  // 安全：使用普通的 JSX 文字節點
  return <div>{textContent}</div>;
}

function ArticlePage({ article }: { article: any }) {
  return (
    <article>
      <h1>{article.title}</h1>
      {/* 安全：使用 textContent 顯示純文字 */}
      <div>{article.body}</div>
    </article>
  );
}

function MarkdownRenderer({ markdown }: { markdown: string }) {
  // 安全：使用 markdown 渲染器搭配淨化
  const html = renderMarkdown(markdown);
  return <div className="markdown-body">{html}</div>;
}

