"""Local upload page (standard library only).

GET  /            upload form
POST /analyze     run the workflow on the uploaded files
POST /analyze-folder  analyze a folder on this machine in place; a completed report's output
                  folder is reopened instead, without reanalyzing
POST /folder-kind JSON {path} -> {report}: whether a folder is a completed report's output folder
POST /browse, /locate-folder, /pick-folder  the folder picker (in-page list, container, macOS dialog)
GET  /runs/<id>/  links to a run's reports; files under it are served read-only
POST /runs/<id>/brief  generate the Security Assistant brief (when an LLM is configured)
POST /runs/<id>/article-briefs  generate article briefs from matched sources
POST /runs/<id>/ask    JSON {question, history} -> {answer, answer_html}
GET  /runs/<id>/radar-status  whether on-demand Radar lookup is configured
POST /runs/<id>/radar  Radar context for an observed IP or domain IOC
GET  /compare     choose saved runs to compare; POST /compare compares them (optionally looking
                  for an IOC CSV again in each one) and opens GET /compare/<time>/
GET/POST /branding     set the name before "VulnScope" and an optional logo (saved per user; password protected)
GET/POST /settings     choose the AI provider and enter its API key (kept in memory only)

Layout: server.py starts it; app.py holds what the server remembers; handler.py is the HTTP
plumbing (gate, CSRF, bodies, responses); routes.py maps paths to views; one module per page:
upload, folders, runs, settings, branding_page, compare_page (the comparison itself is
compare.py).
"""
from .runs import SAVED_SANDBOX
from .server import make_handler, serve

__all__ = ["SAVED_SANDBOX", "make_handler", "serve"]
