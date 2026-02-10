// dangerouslySetInnerHTML: SHOULD trigger the rule
// Pattern: JSX 中使用 dangerouslySetInnerHTML 屬性
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

import React from "react";

function UnsafeComponent({ htmlContent }: { htmlContent: string }) {
  // 不安全：直接使用 dangerouslySetInnerHTML
  return <div dangerouslySetInnerHTML={{ __html: htmlContent }} />;
}

function ArticlePage({ article }: { article: any }) {
  return (
    <article>
      <h1>{article.title}</h1>
      {/* 不安全：文章內容可能包含惡意腳本 */}
      <div dangerouslySetInnerHTML={{ __html: article.body }} />
    </article>
  );
}

function CommentSection({ comment }: { comment: string }) {
  // 不安全：使用者評論未經淨化
  return <p dangerouslySetInnerHTML={{ __html: comment }} />;
}

