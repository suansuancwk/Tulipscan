import time

import ip_scan
class IP_HT:
    def mb(self, dm):  # 直接传入bl即可
        html1 = r'''
        <!doctype html>
<html>
<head>
<meta charset='UTF-8'><meta name='viewport' content='width=device-width initial-scale=1'>

<style type='text/css'>html {overflow-x: initial !important;}:root { --bg-color:#ffffff; --text-color:#333333; --select-text-bg-color:#B5D6FC; --select-text-font-color:auto; --monospace:"Lucida Console",Consolas,"Courier",monospace; --title-bar-height:20px; }
.mac-os-11 { --title-bar-height:28px; }
html { font-size: 14px; background-color: var(--bg-color); color: var(--text-color); font-family: "Helvetica Neue", Helvetica, Arial, sans-serif; -webkit-font-smoothing: antialiased; }
body { margin: 0px; padding: 0px; height: auto; inset: 0px; font-size: 1rem; line-height: 1.42857; overflow-x: hidden; background: inherit; tab-size: 4; }
iframe { margin: auto; }
a.url { word-break: break-all; }
a:active, a:hover { outline: 0px; }
.in-text-selection, ::selection { text-shadow: none; background: var(--select-text-bg-color); color: var(--select-text-font-color); }
#write { margin: 0px auto; height: auto; width: inherit; word-break: normal; overflow-wrap: break-word; position: relative; white-space: normal; overflow-x: visible; padding-top: 36px; }
#write.first-line-indent p { text-indent: 2em; }
#write.first-line-indent li p, #write.first-line-indent p * { text-indent: 0px; }
#write.first-line-indent li { margin-left: 2em; }
.for-image #write { padding-left: 8px; padding-right: 8px; }
body.typora-export { padding-left: 30px; padding-right: 30px; }
.typora-export .footnote-line, .typora-export li, .typora-export p { white-space: pre-wrap; }
.typora-export .task-list-item input { pointer-events: none; }
@media screen and (max-width: 500px) {
  body.typora-export { padding-left: 0px; padding-right: 0px; }
  #write { padding-left: 20px; padding-right: 20px; }
  .CodeMirror-sizer { margin-left: 0px !important; }
  .CodeMirror-gutters { display: none !important; }
}
#write li > figure:last-child { margin-bottom: 0.5rem; }
#write ol, #write ul { position: relative; }
img { max-width: 100%; vertical-align: middle; image-orientation: from-image; }
button, input, select, textarea { color: inherit; font: inherit; }
input[type="checkbox"], input[type="radio"] { line-height: normal; padding: 0px; }
*, ::after, ::before { box-sizing: border-box; }
#write h1, #write h2, #write h3, #write h4, #write h5, #write h6, #write p, #write pre { width: inherit; }
#write h1, #write h2, #write h3, #write h4, #write h5, #write h6, #write p { position: relative; }
p { line-height: inherit; }
h1, h2, h3, h4, h5, h6 { break-after: avoid-page; break-inside: avoid; orphans: 4; }
p { orphans: 4; }
h1 { font-size: 2rem; }
h2 { font-size: 1.8rem; }
h3 { font-size: 1.6rem; }
h4 { font-size: 1.4rem; }
h5 { font-size: 1.2rem; }
h6 { font-size: 1rem; }
.md-math-block, .md-rawblock, h1, h2, h3, h4, h5, h6, p { margin-top: 1rem; margin-bottom: 1rem; }
.hidden { display: none; }
.md-blockmeta { color: rgb(204, 204, 204); font-weight: 700; font-style: italic; }
a { cursor: pointer; }
sup.md-footnote { padding: 2px 4px; background-color: rgba(238, 238, 238, 0.7); color: rgb(85, 85, 85); border-radius: 4px; cursor: pointer; }
sup.md-footnote a, sup.md-footnote a:hover { color: inherit; text-transform: inherit; text-decoration: inherit; }
#write input[type="checkbox"] { cursor: pointer; width: inherit; height: inherit; }
figure { overflow-x: auto; margin: 1.2em 0px; max-width: calc(100% + 16px); padding: 0px; }
figure > table { margin: 0px; }
tr { break-inside: avoid; break-after: auto; }
thead { display: table-header-group; }
table { border-collapse: collapse; border-spacing: 0px; width: 100%; overflow: auto; break-inside: auto; text-align: left; }
table.md-table td { min-width: 32px; }
.CodeMirror-gutters { border-right: 0px; background-color: inherit; }
.CodeMirror-linenumber { user-select: none; }
.CodeMirror { text-align: left; }
.CodeMirror-placeholder { opacity: 0.3; }
.CodeMirror pre { padding: 0px 4px; }
.CodeMirror-lines { padding: 0px; }
div.hr:focus { cursor: none; }
#write pre { white-space: pre-wrap; }
#write.fences-no-line-wrapping pre { white-space: pre; }
#write pre.ty-contain-cm { white-space: normal; }
.CodeMirror-gutters { margin-right: 4px; }
.md-fences { font-size: 0.9rem; display: block; break-inside: avoid; text-align: left; overflow: visible; white-space: pre; background: inherit; position: relative !important; }
.md-fences-adv-panel { width: 100%; margin-top: 10px; text-align: center; padding-top: 0px; padding-bottom: 8px; overflow-x: auto; }
#write .md-fences.mock-cm { white-space: pre-wrap; }
.md-fences.md-fences-with-lineno { padding-left: 0px; }
#write.fences-no-line-wrapping .md-fences.mock-cm { white-space: pre; overflow-x: auto; }
.md-fences.mock-cm.md-fences-with-lineno { padding-left: 8px; }
.CodeMirror-line, twitterwidget { break-inside: avoid; }
.footnotes { opacity: 0.8; font-size: 0.9rem; margin-top: 1em; margin-bottom: 1em; }
.footnotes + .footnotes { margin-top: 0px; }
.md-reset { margin: 0px; padding: 0px; border: 0px; outline: 0px; vertical-align: top; background: 0px 0px; text-decoration: none; text-shadow: none; float: none; position: static; width: auto; height: auto; white-space: nowrap; cursor: inherit; -webkit-tap-highlight-color: transparent; line-height: normal; font-weight: 400; text-align: left; box-sizing: content-box; direction: ltr; }
li div { padding-top: 0px; }
blockquote { margin: 1rem 0px; }
li .mathjax-block, li p { margin: 0.5rem 0px; }
li blockquote { margin: 1rem 0px; }
li { margin: 0px; position: relative; }
blockquote > :last-child { margin-bottom: 0px; }
blockquote > :first-child, li > :first-child { margin-top: 0px; }
.footnotes-area { color: rgb(136, 136, 136); margin-top: 0.714rem; padding-bottom: 0.143rem; white-space: normal; }
#write .footnote-line { white-space: pre-wrap; }
@media print {
  body, html { border: 1px solid transparent; height: 99%; break-after: avoid; break-before: avoid; font-variant-ligatures: no-common-ligatures; }
  #write { margin-top: 0px; padding-top: 0px; border-color: transparent !important; }
  .typora-export * { -webkit-print-color-adjust: exact; }
  .typora-export #write { break-after: avoid; }
  .typora-export #write::after { height: 0px; }
  .is-mac table { break-inside: avoid; }
  .typora-export-show-outline .typora-export-sidebar { display: none; }
}
.footnote-line { margin-top: 0.714em; font-size: 0.7em; }
a img, img a { cursor: pointer; }
pre.md-meta-block { font-size: 0.8rem; min-height: 0.8rem; white-space: pre-wrap; background: rgb(204, 204, 204); display: block; overflow-x: hidden; }
p > .md-image:only-child:not(.md-img-error) img, p > img:only-child { display: block; margin: auto; }
#write.first-line-indent p > .md-image:only-child:not(.md-img-error) img { left: -2em; position: relative; }
p > .md-image:only-child { display: inline-block; width: 100%; }
#write .MathJax_Display { margin: 0.8em 0px 0px; }
.md-math-block { width: 100%; }
.md-math-block:not(:empty)::after { display: none; }
.MathJax_ref { fill: currentcolor; }
[contenteditable="true"]:active, [contenteditable="true"]:focus, [contenteditable="false"]:active, [contenteditable="false"]:focus { outline: 0px; box-shadow: none; }
.md-task-list-item { position: relative; list-style-type: none; }
.task-list-item.md-task-list-item { padding-left: 0px; }
.md-task-list-item > input { position: absolute; top: 0px; left: 0px; margin-left: -1.2em; margin-top: calc(1em - 10px); border: none; }
.math { font-size: 1rem; }
.md-toc { min-height: 3.58rem; position: relative; font-size: 0.9rem; border-radius: 10px; }
.md-toc-content { position: relative; margin-left: 0px; }
.md-toc-content::after, .md-toc::after { display: none; }
.md-toc-item { display: block; color: rgb(65, 131, 196); }
.md-toc-item a { text-decoration: none; }
.md-toc-inner:hover { text-decoration: underline; }
.md-toc-inner { display: inline-block; cursor: pointer; }
.md-toc-h1 .md-toc-inner { margin-left: 0px; font-weight: 700; }
.md-toc-h2 .md-toc-inner { margin-left: 2em; }
.md-toc-h3 .md-toc-inner { margin-left: 4em; }
.md-toc-h4 .md-toc-inner { margin-left: 6em; }
.md-toc-h5 .md-toc-inner { margin-left: 8em; }
.md-toc-h6 .md-toc-inner { margin-left: 10em; }
@media screen and (max-width: 48em) {
  .md-toc-h3 .md-toc-inner { margin-left: 3.5em; }
  .md-toc-h4 .md-toc-inner { margin-left: 5em; }
  .md-toc-h5 .md-toc-inner { margin-left: 6.5em; }
  .md-toc-h6 .md-toc-inner { margin-left: 8em; }
}
a.md-toc-inner { font-size: inherit; font-style: inherit; font-weight: inherit; line-height: inherit; }
.footnote-line a:not(.reversefootnote) { color: inherit; }
.md-attr { display: none; }
.md-fn-count::after { content: "."; }
code, pre, samp, tt { font-family: var(--monospace); }
kbd { margin: 0px 0.1em; padding: 0.1em 0.6em; font-size: 0.8em; color: rgb(36, 39, 41); background: rgb(255, 255, 255); border: 1px solid rgb(173, 179, 185); border-radius: 3px; box-shadow: rgba(12, 13, 14, 0.2) 0px 1px 0px, rgb(255, 255, 255) 0px 0px 0px 2px inset; white-space: nowrap; vertical-align: middle; }
.md-comment { color: rgb(162, 127, 3); opacity: 0.6; font-family: var(--monospace); }
code { text-align: left; vertical-align: initial; }
a.md-print-anchor { white-space: pre !important; border-width: initial !important; border-style: none !important; border-color: initial !important; display: inline-block !important; position: absolute !important; width: 1px !important; right: 0px !important; outline: 0px !important; background: 0px 0px !important; text-decoration: initial !important; text-shadow: initial !important; }
.os-windows.monocolor-emoji .md-emoji { font-family: "Segoe UI Symbol", sans-serif; }
.md-diagram-panel > svg { max-width: 100%; }
[lang="flow"] svg, [lang="mermaid"] svg { max-width: 100%; height: auto; }
[lang="mermaid"] .node text { font-size: 1rem; }
table tr th { border-bottom: 0px; }
video { max-width: 100%; display: block; margin: 0px auto; }
iframe { max-width: 100%; width: 100%; border: none; }
.highlight td, .highlight tr { border: 0px; }
mark { background: rgb(255, 255, 0); color: rgb(0, 0, 0); }
.md-html-inline .md-plain, .md-html-inline strong, mark .md-inline-math, mark strong { color: inherit; }
.md-expand mark .md-meta { opacity: 0.3 !important; }
mark .md-meta { color: rgb(0, 0, 0); }
@media print {
  .typora-export h1, .typora-export h2, .typora-export h3, .typora-export h4, .typora-export h5, .typora-export h6 { break-inside: avoid; }
}
.md-diagram-panel .messageText { stroke: none !important; }
.md-diagram-panel .start-state { fill: var(--node-fill); }
.md-diagram-panel .edgeLabel rect { opacity: 1 !important; }
.md-fences.md-fences-math { font-size: 1em; }
.md-fences-advanced:not(.md-focus) { padding: 0px; white-space: nowrap; border: 0px; }
.md-fences-advanced:not(.md-focus) { background: inherit; }
.typora-export-show-outline .typora-export-content { max-width: 1440px; margin: auto; display: flex; flex-direction: row; }
.typora-export-sidebar { width: 300px; font-size: 0.8rem; margin-top: 80px; margin-right: 18px; }
.typora-export-show-outline #write { --webkit-flex:2; flex: 2 1 0%; }
.typora-export-sidebar .outline-content { position: fixed; top: 0px; max-height: 100%; overflow: hidden auto; padding-bottom: 30px; padding-top: 60px; width: 300px; }
@media screen and (max-width: 1024px) {
  .typora-export-sidebar, .typora-export-sidebar .outline-content { width: 240px; }
}
@media screen and (max-width: 800px) {
  .typora-export-sidebar { display: none; }
}
.outline-content li, .outline-content ul { margin-left: 0px; margin-right: 0px; padding-left: 0px; padding-right: 0px; list-style: none; }
.outline-content ul { margin-top: 0px; margin-bottom: 0px; }
.outline-content strong { font-weight: 400; }
.outline-expander { width: 1rem; height: 1.42857rem; position: relative; display: table-cell; vertical-align: middle; cursor: pointer; padding-left: 4px; }
.outline-expander::before { content: ""; position: relative; font-family: Ionicons; display: inline-block; font-size: 8px; vertical-align: middle; }
.outline-item { padding-top: 3px; padding-bottom: 3px; cursor: pointer; }
.outline-expander:hover::before { content: ""; }
.outline-h1 > .outline-item { padding-left: 0px; }
.outline-h2 > .outline-item { padding-left: 1em; }
.outline-h3 > .outline-item { padding-left: 2em; }
.outline-h4 > .outline-item { padding-left: 3em; }
.outline-h5 > .outline-item { padding-left: 4em; }
.outline-h6 > .outline-item { padding-left: 5em; }
.outline-label { cursor: pointer; display: table-cell; vertical-align: middle; text-decoration: none; color: inherit; }
.outline-label:hover { text-decoration: underline; }
.outline-item:hover { border-color: rgb(245, 245, 245); background-color: var(--item-hover-bg-color); }
.outline-item:hover { margin-left: -28px; margin-right: -28px; border-left: 28px solid transparent; border-right: 28px solid transparent; }
.outline-item-single .outline-expander::before, .outline-item-single .outline-expander:hover::before { display: none; }
.outline-item-open > .outline-item > .outline-expander::before { content: ""; }
.outline-children { display: none; }
.info-panel-tab-wrapper { display: none; }
.outline-item-open > .outline-children { display: block; }
.typora-export .outline-item { padding-top: 1px; padding-bottom: 1px; }
.typora-export .outline-item:hover { margin-right: -8px; border-right: 8px solid transparent; }
.typora-export .outline-expander::before { content: "+"; font-family: inherit; top: -1px; }
.typora-export .outline-expander:hover::before, .typora-export .outline-item-open > .outline-item > .outline-expander::before { content: "−"; }
.typora-export-collapse-outline .outline-children { display: none; }
.typora-export-collapse-outline .outline-item-open > .outline-children, .typora-export-no-collapse-outline .outline-children { display: block; }
.typora-export-no-collapse-outline .outline-expander::before { content: "" !important; }
.typora-export-show-outline .outline-item-active > .outline-item .outline-label { font-weight: 700; }
.md-inline-math-container mjx-container { zoom: 0.95; }



.cm-s-inner.CodeMirror {
    background-color: #003444;
    color: #EEFFFF;
    padding: 0.75rem 0.15rem 0.75rem 0.15rem;
    border-radius: 6px;
}

#write .CodeMirror-cursors .CodeMirror-cursor {
    border-left: 2px solid #f0f0f0;
}

.cm-s-inner .cm-header, .cm-s-inner.cm-header {
    color: #A77DF4;
}

.cm-s-inner .CodeMirror-gutters {
    background: #003444;
    color: #546E7A;
    border: none;
}

.code-tooltip {
    box-shadow: 0 1px 1px 0 rgba(0, 28, 36, .3);
    border-top: 1px solid #eef2f2;
    color: #fff;
    background: #003444;
    border-radius: 6px;
}

.cm-s-inner .CodeMirror-guttermarker,
.cm-s-inner .CodeMirror-guttermarker-subtle,
.cm-s-inner .CodeMirror-linenumber {
    color: #546E7A;
}

.cm-s-inner .CodeMirror-cursor {
    border-left: 1px solid #FFCC00;
}

.cm-s-inner.cm-fat-cursor .CodeMirror-cursor {
    background-color: #5d6d5c80 !important;
}
.cm-s-inner .cm-animate-fat-cursor {
    background-color: #5d6d5c80 !important;
}

.cm-s-inner div.CodeMirror-selected {
    background: rgba(128, 203, 196, 0.2);
}

.cm-s-inner.CodeMirror-focused div.CodeMirror-selected {
    background: rgba(128, 203, 196, 0.2);
}

.cm-s-inner .CodeMirror-line::selection,
.cm-s-inner .CodeMirror-line>span::selection,
.cm-s-inner .CodeMirror-line>span>span::selection {
    background:  rgba(0,178,123,0.2);
}

.cm-s-inner .CodeMirror-line::-moz-selection,
.cm-s-inner .CodeMirror-line>span::-moz-selection,
.cm-s-inner .CodeMirror-line>span>span::-moz-selection {
    background: rgba(0,178,123,0.2);
}

.cm-s-inner .CodeMirror-activeline-background {
    background: #003444;
}

.cm-s-inner .cm-keyword {
    color: #C792EA;
}

.cm-s-inner .cm-operator {
    color: #E9EDED;
}

.cm-s-inner .cm-variable-2 {
    color: #80CBC4;
}

.cm-s-inner .cm-variable-3,
.cm-s-inner .cm-type {
    color: #82B1FF;
}

.cm-s-inner .cm-builtin {
    color: #DECB6B;
}

.cm-s-inner .cm-atom {
    color: #F77669;
}

.cm-s-inner .cm-number {
    color: #F77669;
}

.cm-s-inner .cm-def {
    color: #00AEC4;
}

.cm-s-inner .cm-string {
    color: #C3E88D;
}

.cm-s-inner .cm-string-2 {
    color: #80CBC4;
}

.cm-s-inner .cm-comment {
    color: #AEBBC2;
}

.cm-s-inner .cm-variable {
    color: #82B1FF;
}

.cm-s-inner .cm-tag {
    color: #80CBC4;
}

.cm-s-inner .cm-meta {
    color: #80CBC4;
}

.cm-s-inner .cm-attribute {
    color: #FFCB6B;
}

.cm-s-inner .cm-property {
    color: #80CBAE;
}

.cm-s-inner .cm-qualifier {
    color: #DECB6B;
}

.cm-s-inner .cm-variable-3,
.cm-s-inner .cm-type {
    color: #DECB6B;
}

.cm-s-inner .cm-error {
    color: #FFFFFF;
    background-color: #FF5370;
}

.cm-s-inner .CodeMirror-matchingbracket {
    text-decoration: underline;
    color: white !important;
}
@import url('file:///C://Users//suansuan//AppData//Roaming//Typora/themes/');
@import url('file:///C://Users//suansuan//AppData//Roaming//Typora/themes/');

/** color vars **/
:root {
  /* system vars*/
  --primary-color: #f0f0f0; /* color of primary buttons */
  --side-bar-bg-color: #003444;
  --active-file-bg-color: #004144; /* sidebar active & hover */
  --active-file-text-color: #ffffff;
  --active-file-border-color: #757575;
  --item-hover-text-color: #fff;
  --item-hover-bg-color: #005C44;  /* sidebar footer item hover*/
  --control-text-color: #ddd;
  --control-text-hover-color: #fff;
  --monospace: 'SourceHanSansSC','JetBrains Mono', -apple-system, sans-serif;

  /* custom vars */
  --theme-primary-color: #00997B; /* rgb(0, 153, 123) */
  --white-color: #fff;

  /* head */
  --head-text-color: #333444;
  --h1-text-color: rgba(0, 52, 68, 0.9);
  --h5-text-color: var(--theme-primary-color);
  --h6-text-color: rgba(0, 153, 123, 0.838);
  --head-prefix-color: #D0D0D0;

  /* text */
  --text-color: #363C42;
  --text-search-hit-color: rosybrown;

  /* highlight */
  --highlight-bg-color: #FFF3F3;
  --highlight-text-color: #FF2F2F;

  /* a link */
  --a-text-color: var(--theme-primary-color);

  /* annotate */
  --annotate-text-color: #8CAA16;

  /* inline code */
  --inline-code-bg-color: #f3f3f3;
  --inline-code-text-color: #00769A;

  /* selection */
  --selection-text-color: rgba(0, 153, 123, 0.2);

  /* check-box */
  --checked-text-color: #ADB5BD;
  --line-through-color: #CFD4DA;
  --border-color: #868E96;

  /* table */
  --table-border-color: #DADCDE;
  --table-cell-bg-color:rgba(0, 153, 123, 0.03);

  /* quote */
  --quote-bg-color: rgba(0, 153, 123, 0.05);
  --quote-text-color: #81888D ;

  /* sidebar */
  --sidebar-footer-dropdown-menu-border-color: #212529;
  --sidebar-footer-dropdown-menu-item-border-color: #ADB5BD;
  --sidebar-footer-item-hover-bg-color: #004544;
  --siderbar-dropdown-menu-text-color: #fff;

  /* sidebar resizer */
  --sidebar-resizer: #6eace2;

  /*--window-border: #e5e5e5;*/
  --window-border: #1F6F57; /*sidebar layout border*/
}


/* global && write area */
#write {
  position: static;
  width: 90%;
  max-width: 900px;
  line-height: 1.6;
  padding: 36px 0 70px;
}
html, body, #write {
  background: var(--white-color);
  font-family: 'SourceHanSansSC','JetBrains Mono', -apple-system, sans-serif;
}
p {
  font-size: 1em;
  font-family: 'SourceHanSansSC', 'JetBrains Mono', -apple-system, sans-serif;
  line-height: 1.6;
  color: var(--text-color);
}


/* search match active*/
.md-search-hit.md-search-select{
  background-color: var(--text-search-hit-color);
}


/* heading */
h1, h2, h3, h4, h5, h6 {
  width: auto;
  line-height: 2;
  font-style: normal;
  margin-top: 14px;
  margin-bottom: 14px;
}
h2, h3, h4 {
  color: var(--head-text-color);
}
h2::before, h3::before, h4::before, h5::before, h6::before,
h2.md-focus::before, h3.md-focus::before, h4.md-focus::before, h5.md-focus::before, h6.md-focus::before {
  position: absolute;
  right: calc(100% + 10px);
  top: 50%;
  transform: translateY(-50%);
  color: var(--head-prefix-color);
  font-size: 0.8rem;
  font-weight: bold;
  font-variant: 'small-caps';
  line-height: 2;
  padding: 0;
  border: 0;
}

#write h1 {
  font-size: 2.1rem;
  font-weight: 900;
  text-align: center;
  color: var(--h1-text-color);
}
#write h1>span{
  position: relative;
  display: inline-block;
}
#write h1>span:after{
  content: '';
  display: block;
  position: absolute;
  border-top: 3px double var(--h1-text-color);
  height: 3px;
  width: 15rem;
  max-width: 80%;
  left: 50%;
  transform: translateX(-50%);
}

#write h2 {
  font-size: 1.7rem;
  font-weight: 800;
}
#write>h2::before {
  content: 'H2';
}

#write h3 {
  font-size: 1.4rem;
  font-weight: 800;
}
#write>h3::before {
  content: 'H3';
}

#write h4, #write h5, #write h5 {
  font-size: 1.2rem;
  font-weight: bold;
}
#write h5 {
  color: var(--h5-text-color);
}
#write h6 {
  color: var(--h6-text-color);
}
#write>h4::before {
  content: 'H4';
}
#write>h5::before {
  content: 'H5';
}
#write>h6::before {
  content: 'H6';
}


/* inline element */
#write a {
  color: var(--a-text-color);
  cursor: pointer;
  padding: 0 3px 0 3px;
  text-decoration: none;
}
#write a:hover {
  text-decoration: none;
  border-bottom: 1px solid;
}

strong {
  font-weight: 700;
}

mark {
  background: var(--highlight-bg-color);
  color: var(--highlight-text-color);
  font-weight: 500;
  padding: 0 2px 0 2px;
  margin: 0 2px 0 2px;
  border-radius: 2px;
}

span.md-comment {
  color: var(--annotate-text-color);
}

/* footnote */
sup.md-footnote {
  color: var(--a-text-color);
  background-color: var(--white-color);
}
.footnotes .md-def-name {
  padding-right: 4ch;
}

/* inline code */
#write code{
  margin: 0 2px;
  padding: 0px 4px;
  font-size: 0.95rem;
  background: var(--inline-code-bg-color);
  display: inline;
  vertical-align: top;
  line-height: 1.6;
  border-radius: 6px;
  font-weight: 700;
  color: var(--inline-code-text-color);
}
.md-hover-tip .code-tooltip-content, .md-hover-tip .md-arrow:after {
  background: var(--side-bar-bg-color);
}
#write *[mdtype="heading"] code{
  font-size: inherit!important;
  vertical-align: baseline;
}

img {
  margin-top: 0.2rem;
  margin-bottom: 0.2rem;
}
p>.md-image:only-child:not(.md-img-error) img, p>img:only-child {
  display: block;
  margin: unset;
}
/* operation img tip dialog */
#user-context-menu>li>a, .dropdown-menu>li>a {
  color: var(--theme-primary-color);
  font-weight: 500;
}
#user-context-menu>li>a:hover, #user-context-menu>li.active>a {
  background: var(--theme-primary-color);
  color: #fff;
}
#zoom-img-menu.context-menu.dropdown-menu>li>a:hover,
#zoom-img-menu.context-menu.dropdown-menu>li.active>a {
  background: var(--theme-primary-color);
  color: #fff;
}
#zoom-img-menu.dropdown-menu .divider {
  background: var(--theme-primary-color);
}

/* underline */
#write u {
  text-decoration: none;
}
#write u>span {
  border-bottom: 1px solid;
}

/* selection */
span::selection, *::selection {
  background: var(--selection-text-color);
}


/* block element */
/* YAML front */
pre.md-meta-block {
  font-size: .85rem;
  color: var(--quote-text-color);
  background: var(--quote-bg-color);
  padding: 1rem;
  border-radius: 8px;
}

/* toc */
#write .md-toc {
  font-size: 1rem;
}
#write a.md-toc-inner {
  color: var(--theme-primary-color);
}
#write a.md-toc-inner:hover {
  text-decoration: underline;
  border-bottom: none;
}
p.md-toc-content {
  line-height: 1.8;
  font-weight: 500;
}
.md-toc-h2 .md-toc-inner {
  margin-left: 1em;
}
.md-toc-h3 .md-toc-inner {
  margin-left: 2em;
}
.md-toc-h4 .md-toc-inner {
  margin-left: 3em;
}
.md-toc-h5 .md-toc-inner {
  margin-left: 4em;
}
.md-toc-h6 .md-toc-inner {
  margin-left: 5em;
}

/* quote */
blockquote {
  position: relative;
  padding: 1rem;
  background-color: var(--quote-bg-color);
  border-radius: 6px;
  line-height: 1;
}
blockquote p {
  color: var(--quote-text-color);
  margin: 0 ;
}
blockquote::before {
  content: '';
  position: absolute;
  top: 0rem;
  left: 0rem;
  height: 100%;
  width: .30rem;
  background: var(--theme-primary-color);
  border-top-left-radius: 6px;
  border-bottom-left-radius: 6px;
}

/* hr */
div[mdtype='hr'] {
  text-align: center;
}
hr {
  border-top: 1px dashed var(--theme-primary-color);
  transform: scaleY(0.5);
  width: 90%;
}

/* ul, ol */
ul>li>ul>li {
  list-style-type: circle;
}
ul>li>ul>li>ul>li {
  list-style-type: disc;
}
ul>li>ul>li>ul>li>ul>li {
  list-style-type: circle;
}
ul>li>ul>li>ul>li>ul>li>ul>li {
  list-style-type: disc;
}
ul>li>ul>li>ul>li>ul>li>ul>li>ul>li {
  list-style-type: circle;
}

ol ul li {
  list-style-type: circle;
}
ol ul>li>ul>li {
  list-style-type: disc;
}
ol ul>li>ul>li>ul>li {
  list-style-type: circle;
}
ol ul>li>ul>li>ul>li>ul>li {
  list-style-type: disc;
}
ol ul>li>ul>li>ul>li>ul>li>ul>li {
  list-style-type: circle;
}
ol ul>li>ul>li>ul>li>ul>li>ul>li>ul>li {
  list-style-type: circle;
}

ol>li>ol>li {
  list-style-type: lower-alpha;
}
ol>li>ol>li>ol>li {
  list-style-type: decimal;
}
ol>li>ol>li>ol>li>ol>li {
  list-style-type: lower-alpha;
}
ol>li>ol>li>ol>li>ol>li>ol>li {
  list-style-type: decimal;
}
ol>li>ol>li>ol>li>ol>li>ol>li>ol>li {
  list-style-type: lower-alpha;
}
ol>li>ol>li>ol>li>ol>li>ol>li>ol>li>ol>li {
  list-style-type: decimal;
}

/* task list */
.task-list-item.md-task-list-item {
  list-style-type: none;
}
.md-task-list-item>input, #write .md-task-list-item>input[type=checkbox] {
  margin-left: -1.6rem;
  width: 0.5rem;
  height: 0.5rem;
}

.md-task-list-item>input:before {
  border: 2px solid var(--border-color);
  width: 1rem;
  height: 1rem;
  background:  var(--white-color);
  content: ' ';
  transition: background-color 200ms ease-in-out;
  display: block;
}
.md-task-list-item>input:checked:before,
.md-task-list-item>input[checked]:before {
  background: var(--theme-primary-color);
  border-width: 1px;
  transition: background-color 200ms ease-in-out;
  border: 2px solid var(--theme-primary-color);
}
.md-task-list-item>input[checked]+p {
  color: var(--checked-text-color);
  text-decoration: line-through;
  text-decoration-color: var(--line-through-color);
}

.md-task-list-item>input:checked:after,
.md-task-list-item>input[checked]:after {
  opacity: 1;
}
.md-task-list-item>input:after {
  opacity: 1;
  -webkit-transition: opacity 0.05s ease-in-out;
  -moz-transition: opacity 0.05s ease-in-out;
  transition: opacity 0.05s ease-in-out;
  -webkit-transform: rotate(-45deg);
  -moz-transform: rotate(-45deg);
  transform: rotate(-45deg);
  position: absolute;
  top: 0.25rem;
  left: 0.19rem;
  width: 0.6rem;
  height: 0.375rem;
  border: 2px solid var(--white-color);
  border-top: 0;
  border-right: 0;
  content: ' ';
  opacity: 0;
}

/* table */
.md-table-edit .btn-default {
  color: inherit;
}
table.md-table {
  width: auto;
  min-width: 80%;
}
table tr:nth-child(2n), table thead  {
  background-color: var(--table-cell-bg-color);
}
table thead {
  font-weight: 900;
}

table tbody tr {
  border-bottom: 1px solid var(--table-border-color);
}
table tr:first-of-type {
  border-top: 1px solid var(--table-border-color);
}
table tr th, table tr td {
  border-left: 1px solid var(--table-border-color);
  padding: 6px 13px;
}
table tr th:last-of-type, table tr td:last-of-type {
  border-right: 1px solid var(--table-border-color);
}

/* code */
.auto-suggest-container {
  border: 1px solid var(--theme-primary-color);
}
.auto-suggest-container li:hover, .auto-suggest-container li.active {
  color: #fff;
  background: var(--theme-primary-color);
}


/* outline */
#toc-dropmenu {
  width: 400px;
}
#toc-dropmenu.open {
  background: var(--side-bar-bg-color);
  color: var(--white-color);
}
#toc-dropmenu .outline-title-wrapper .outline-title {
  font-weight: 900;
}
#toc-dropmenu .outline-title-wrapper {
  height: 2.5rem;
}
.outline-title-wrapper .btn {
  color: var(--white-color);
  line-height: 2.5rem;
  vertical-align: middle;
}

.dropdown-menu .divider {
  background: var(--white-color);
}
.outline-item:hover {
  background: var(--active-file-bg-color);
}
.outline-expander {
  display: inline-block;
  margin-right: 0.4rem;
}
.outline-label {
  display: inline-block;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  width: calc(100% - 1.5rem);
}
.outline-label:hover {
  text-decoration: none;
}


/* notification */
#md-notification:before {
  top: 18px;
}
#md-notification p {
  color: var(--theme-primary-color);
  font-weight: 500;
}
.btn-default {
  background: var(--theme-primary-color);
  color: var(--white-color);
}
.btn-default.active, .btn-default.focus, .btn-default:active,
.btn-default:focus, .btn-default:hover,
.open>.dropdown-toggle.btn-default {
  color: var(--theme-primary-color);
  border: 1px solid var(--theme-primary-color);
  background: var(--white-color);
}


/* sidebar */
.sidebar-menu {
  color: var(--siderbar-dropdown-menu-text-color);
}
.sidebar-menu .sidebar-content  .sidebar-content-content {
  font-weight: 500;
}

#file-library-tree .file-tree-node {
  padding-left: 1.5em;
  color: var(--control-text-color);
  padding-top: 6px;
  white-space: nowrap;
  line-height: 1.5;
}
.file-tree-node .file-node-content:hover {
  cursor: pointer;
}
#file-library-tree .file-node-expanded>.file-node-content>.fa-folder:before {
  content: '\f07c';
}
#file-library-tree .fa-file-text-o:before {
  content: '\f1ce'
}

.file-tree-node.active>.file-node-background {
  border-left: 4px solid var(--theme-primary-color);
}
#typora-sidebar .file-list-item.file-library-node:not(.active):hover {
  background: var(--active-file-bg-color);
}
#typora-sidebar .file-tree-node.file-library-file-node:not(.active):hover .file-node-background {
  background: var(--active-file-bg-color);
  height: 2.2rem;
}

/* siderbar footer*/
.sidebar-footer-main-item #sidebar-files-menu {
  border: 1px solid var(--sidebar-footer-dropdown-menu-border-color);
}
.sidebar-menu  .dropdown-menu>li>a, .sidebar-menu .dropdown-menu>li>a:focus, .sidebar-menu .dropdown-menu>li>a:hover {
  color: var(--siderbar-dropdown-menu-text-color);
}
.dropdown-menu>li>a:hover {
  background: var(--active-file-bg-color);
}
.sidebar-footer-main-item .dropdown-menu .menuitem-group-label {
  font-weight: 500;
}
.dropdown-menu .selected-folder-menu-item a:after {
  color: var(--theme-primary-color);
}
.file-sort-item .ty-side-sort-btn {
  cursor: pointer;
}
#sidebar-files-menu>.show+.menuitem-group-label.show {
  border-top: 1px solid var(--sidebar-footer-dropdown-menu-item-border-color);
}
.footer-item:hover, .sidebar-footer-item:hover {
  background: var(--sidebar-footer-item-hover-bg-color);
}

/* sidebar search*/
.sidebar-menu .ty-sidebar-search-panel #file-library-search-input {
  color: var(--white-color);
}


/* resizer */
#typora-sidebar-resizer.dragging{
  color: var(--sidebar-resizer);
}


/* print style */
@media print {
  .typora-export * {
    -webkit-print-color-adjust: exact;
  }

  #write>h1::before, #write>h2::before, #write>h3::before, #write>h4::before, #write>h5::before, #write>h6::before {
    content: '';
    bottom: 1rem;
  }

  #write u {
    text-decoration: none;
  }
  #write u>span {
    border-bottom: 1px solid;
  }
}


/* source code */
#typora-source {
  font-family: 'SourceHanSansSC','JetBrains Mono', -apple-system, sans-serif;
  line-height: 1.6;
}
#typora-source .cm-header {
  color: var(--theme-primary-color);
}



</style><title>ip分析报告</title>
</head>
<body class="typora-export os-windows">
<img src="logo3.png" width="200" height="88" />
  <div class="typora-export-content">
    <div id="write" class="">
      <h1 id="ip基本分析"><span>远程ip分析</span></h1>
      <p>&nbsp;</p>
      <figure>
        <table>
          <thead>
            <tr>
              <th style="text-align: center"><span>ip</span></th>
              <th style="text-align: center"><span>国家</span></th>
              <th style="text-align: center"><span>区域</span></th>
              <th style="text-align: center"><span>经纬度</span></th>
              <th style="text-align: center"><span>机构</span></th>
            </tr>
          </thead>
          '''
        html2 = '''
        </table>
      </figure>
      <p>&nbsp;</p>
    </div>
  </div>
</body>

</html>
'''
        html = html1 + dm + html2
        ti = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()).replace(':','-')
        try:
            with open('./iphtml/'+ ti +'.html', 'w', encoding='utf-8') as file:
                file.write(html)
                file.close()
        except:
            with open('./iphtml/'+ ti +'.html', 'w', encoding='gbk') as file:
                file.write(html)
                file.close()
        print('\033[1;35m' + '>>>ip报告生成完毕!!!' + '\033[0m')

    def bl(self, sj):  # sj格式:[['xx','xx','xx','xx','xx'],.....]
        dm = '''
        '''
        test = '''
                <tbody>
                    <tr>
                      <td style="text-align: center"><span>{ip}</span></td>
                      <td style="text-align: center"><span>{gj}</span></td>
                      <td style="text-align: center"><span>{cs}</span></td>
                      <td style="text-align: center"><span>{jwd}</span></td>
                      <td style="text-align: center">
                        <span>{jg}</span>
                      </td>
                    </tr>
                </tbody>
        '''

        for i in sj:
            if i is None:
                print('*****')
            else:
                ml = test.format(ip=i[0], gj=i[1], cs=i[2], jwd=i[3], jg=i[4])
                dm = dm + ml
        return dm

# if __name__ == '__main__':
#     app1 = ip_scan.IPscan()
#     app2 = IP_HT()
#     # text=[['40.119.211.203', '新加坡', 'Central Singapore', '1.283,103.833', 'Microsoft Azure Cloud (southeastasia)'], ['184.26.156.30', '美国', '加州', '37.3388,-121.8916', 'Akamai Technologies, Inc.'], ['117.18.237.29', '台湾', '台北市', '25.0504,121.5324', 'EdgeCast Networks, Inc'], ['13.226.253.60', '美国', '加州', '34.0522,-118.244', 'AWS CloudFront (GLOBAL)'], ['182.92.187.217', '中国', '北京市', '39.9075,116.3972', 'Aliyun Computing Co., LTD'], ['103.215.142.62', '中国', '北京市', '39.9042,116.407', 'Shenzhen Yunjie Network Co., Ltd.'], ['103.215.142.67', '中国', '北京市', '39.9042,116.407', 'Shenzhen Yunjie Network Co., Ltd.'], ['39.106.32.246', '中国', '北京市', '39.9075,116.3972', 'Aliyun Computing Co., LTD'], ['101.201.173.208', '中国', '北京市', '39.9075,116.3972', 'Aliyun Computing Co., LTD'], ['59.110.175.195', '中国', '北京市', '39.9075,116.3972', 'Aliyun Computing Co., LTD'], ['39.96.132.69', '中国', '北京市', '39.9075,116.3972', 'Aliyun Computing Co., LTD'], ['47.95.163.80', '中国', '北京市', '39.9075,116.3972', 'Aliyun Computing Co., LTD'], ['140.143.49.61', '中国', '广东', '22.5431,114.058', 'Tencent cloud computing (Beijing) Co., Ltd.'], ['39.97.4.86', '中国', '北京市', '39.9075,116.3972', 'Aliyun Computing Co., LTD'], ['52.231.199.126', '韩国', '釜山广域市', '35.1796,129.0756', 'Microsoft Azure Cloud (koreasouth)'], ['52.98.81.178', '日本', 'Ōsaka', '34.6937,135.5022', 'Microsoft Corporation'], ['204.79.197.219', '加拿大', '安大略', '43.6532,-79.3832', 'Microsoft Corporation'], ['151.101.0.223', '美国', '加州', '37.721,-122.391', 'Fastly'], ['49.4.40.61', '中華人民共和國', '北京市', '39.9042,116.4073', 'Huawei Public Cloud Service'], ['13.226.253.27', '美国', '加州', '34.0522,-118.244', 'AWS CloudFront (GLOBAL)'], ['23.204.146.163', '美国', '加州', '34.0544,-118.2441', 'Akamai Technologies, Inc.']]
#     app2.mb(app2.bl(app1.hq_ip()))
