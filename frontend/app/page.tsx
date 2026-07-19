"use client";
import { useEffect, useState } from "react";
import { isLoggedIn, clearToken } from "@/lib/api";
import LoginPage from "../components/LoginPage";
import Dashboard from "../components/Dashboard";

export default function Home() {
  const [loggedIn, setLoggedIn] = useState(false);
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
    setLoggedIn(isLoggedIn());
  }, []);

  if (!mounted) return null;

  return loggedIn ? (
    <Dashboard onLogout={() => { clearToken(); setLoggedIn(false); }} />
  ) : (
    <LoginPage onLogin={() => setLoggedIn(true)} />
  );
}