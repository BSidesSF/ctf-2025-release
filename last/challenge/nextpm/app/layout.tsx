import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import { buttonVariants } from '@/components/ui/button';

import UserContextComponent from "@/components/usercontext";

import "./globals.css";
import Link from "next/link";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "Next Password Manager",
  description: "next-gen password manager",
};

export default async function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased`}>

        <UserContextComponent>
          <div className="min-h-screen bg-gray-100 dark:bg-gray-800 flex flex-col">
            <header className="bg-white dark:bg-black shadow-md py-4 px-8 flex justify-between items-center">
              <h1 className="text-2xl font-bold text-gray-800 dark:text-gray-100">NextPM</h1>
              <nav>
              <Link className={buttonVariants({ variant: "outline" })} href="/login">Login</Link>
              </nav>
            </header>
            
            {children}
          </div>
        </UserContextComponent>
        <footer className="bg-white dark:bg-black shadow-inner py-4 text-center text-gray-500 text-sm">
          &copy; {new Date().getFullYear()} NextPM. All rights reserved.
        </footer>
      </body>
    </html>
  );
}
