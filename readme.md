# Chatter – A Modern Social Media Platform

[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://python.org)
[![Flask](https://img.shields.io/badge/flask-2.3.3-green)](https://flask.palletsprojects.com)
[![License](https://img.shields.io/badge/license-MIT-yellow)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)](https://github.com/enockdeghost/chatter/pulls)

Chatter is a full‑featured social media web application inspired by Twitter/X, Instagram, and TikTok. It allows users to share text posts, images, short videos (reels), ephemeral status updates, create polls, follow friends, send messages, and more – all in a sleek, dark‑themed interface.

---

## ✨ Features

### Core Social Features
- **User Accounts** – Sign up, login, secure password hashing, profile customization (bio, location, website, profile/cover pictures)
- **Posts** – Text posts with images, character counter (280), hashtag & mention detection
- **Interactions** – Like, comment, bookmark, share posts
- **Follow System** – Follow/unfollow users, mutual connections, follower/following lists
- **Blocking & Reporting** – Block users, report content (with reason)
- **Notifications** – Real‑time notifications for likes, comments, follows, mentions, messages
- **Messaging** – Private one‑to‑one messaging with read receipts and unread counts

### Rich Media & Ephemeral Content
- **Reels** – Upload short videos (up to 60 seconds) with captions, music, location; view count, like, comment, share
- **Status** – 24‑hour disappearing text/image/video statuses; view tracking, seen/unseen indicators
- **Polls** – Create multi‑question polls with various types (single choice, multiple choice, quiz)

### Discovery & Organisation
- **Trending** – Trending hashtags and popular posts
- **Search** – Search for users, posts, lists; recent searches stored locally
- **Lists** – Create public/private lists of users to organise your feed
- **Bookmarks** – Save posts for later
- **Pinned Posts** – Pin a post to the top of your profile

### Additional Features
- **QR Codes** – Generate a personal QR code that others can scan to instantly follow you (HMAC‑secured)
- **Find Friends from Contacts** – Upload a vCard (.vcf) to discover which contacts are already on Chatter
- **Admin Panel** – Manage users, posts, reports (with admin privileges)
- **Service Worker** – Offline caching of images/videos for better performance
- **Responsive Design** – Mobile‑first, works beautifully on all devices
- **Dark Theme** – Eye‑friendly dark mode with custom CSS variables

---

## 🛠️ Tech Stack

| Category       | Technologies |
|----------------|--------------|
| **Backend**    | Python 3.10+, Flask, Flask‑SQLAlchemy, Flask‑Login, Werkzeug |
| **Database**   | SQLite (development), easily switchable to PostgreSQL/MySQL |
| **Frontend**   | Bootstrap 5, jQuery, Font Awesome, custom CSS (CSS variables) |
| **Real‑time**  | (Optional) Flask‑SocketIO for live features |
| **Media**      | Pillow (image processing), qrcode[pil] for QR generation |
| **Security**   | HMAC for signed URLs, Werkzeug password hashing, secure cookies |
| **Utilities**  | python‑dotenv (environment variables), vobject (vCard parsing) |

---

## 🚀 Getting Started

### Prerequisites
- Python 3.10 or higher
- pip (Python package manager)
- Git (optional)
