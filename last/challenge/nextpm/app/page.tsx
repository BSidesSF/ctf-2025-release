import React from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { ShieldCheck, KeyRound, Lock } from 'lucide-react';

export default function HomePage() {
  return (
      <main className="flex-1 flex flex-col items-center justify-center text-center px-4">
        <h2 className="text-4xl md:text-5xl font-extrabold text-gray-900 dark:text-gray-200 mb-4">Your Passwords, Secured.</h2>
        <p className="text-gray-600 dark:text-gray-400 text-lg max-w-2xl mb-6">
          Next Password Manager keeps your passwords safe and accessible across all your devices. No more forgetting or reusing weak passwords.
        </p>
        <Button size="lg" className="mb-12">Create Your Vault</Button>

        <div className="grid md:grid-cols-3 gap-6">
          {/* Feature 1 */}
          <Card className="shadow-sm">
            <CardHeader>
              <ShieldCheck className="w-10 h-10 text-blue-500 mx-auto" />
              <CardTitle className="text-xl mt-2">End-to-End Encryption</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-gray-600">
                Your data is encrypted before it leaves your device, ensuring complete privacy and security.
              </p>
            </CardContent>
          </Card>

          {/* Feature 2 */}
          <Card className="shadow-sm">
            <CardHeader>
              <KeyRound className="w-10 h-10 text-green-500 mx-auto" />
              <CardTitle className="text-xl mt-2">One-Click Autofill</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-gray-600">
                Log in to your accounts instantly with our seamless browser extension and mobile integration.
              </p>
            </CardContent>
          </Card>

          {/* Feature 3 */}
          <Card className="shadow-sm">
            <CardHeader>
              <Lock className="w-10 h-10 text-red-500 mx-auto" />
              <CardTitle className="text-xl mt-2">Secure Vault</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-gray-600">
                Store passwords, notes, and sensitive data safely in your personal encrypted vault.
              </p>
            </CardContent>
          </Card>
        </div>
      </main>

  );
}
