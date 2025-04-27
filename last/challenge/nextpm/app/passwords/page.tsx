'use client';

import { useState, useContext, useEffect } from "react";
import { KeySet } from "@/lib/keybagdata";
import { UserContext } from "@/lib/context";
import { simpleHash } from "@/lib/stringutils";
import { redirect } from "next/navigation";

import {
  Card,
  CardContent,
  CardFooter,
} from "@/components/ui/card";

import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { EyeIcon, EyeOffIcon } from 'lucide-react';

interface PasswordProps {
    site: string;
    username: string;
    password: string;
}

interface PasswordBoxProps extends PasswordProps {
    onSave?: (props: PasswordProps) => null;
}

function PasswordBox({site, username, password, onSave}: PasswordBoxProps) {
  const hval = simpleHash(site);
  const [siteState, updateSite] = useState(site);
  const [usernameState, updateUsername] = useState(username);
  const [passwordState, updatePassword] = useState(password);
  const [showPassword, setShowPassword] = useState(false);
  const saveFn = () => {
    if (typeof onSave === "function") {
      onSave({
        site: siteState,
        username: usernameState,
        password: passwordState,
      });
    }
  };
  const saveButton = (typeof onSave === "function") ? (<Button onClick={saveFn}>Save</Button>) : (<></>);
  return (
    <Card>
      <CardContent>
        <form>
          <div className="grid w-full items-center gap-4">
              <div className="flex flex-col space-y-1.5">
                <Label htmlFor={"site-"+hval}>Site</Label>
                <Input id={"site-"+hval} placeholder="URL" value={siteState} onChange={event=>updateSite(event.target.value)} disabled={true}/>
              </div>
              <div className="flex flex-col space-y-1.5">
                <Label htmlFor={"username-"+hval}>Username</Label>
                <Input id={"username-"+hval} placeholder="Username" value={usernameState} onChange={event=>updateUsername(event.target.value)} />
              </div>
              <div className="flex flex-col space-y-1.5">
                <Label htmlFor={"password-"+hval}>Password</Label>
                <div className="relative">
                  <Input id={"password-"+hval} type={showPassword ? "text" : "password"} placeholder="Username" value={passwordState} onChange={event=>updatePassword(event.target.value)} />
                  <button
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute inset-y-0 right-0 flex items-center pr-2"
                  >
                    {showPassword ? <EyeOffIcon className="h-4 w-4" /> : <EyeIcon className="h-4 w-4" />}
                  </button>
                </div>
              </div>
          </div>
        </form>
      </CardContent>
      <CardFooter>
        {saveButton}
      </CardFooter>
    </Card>
  );
}

export default function PasswordPage() {
  const userContext = useContext(UserContext);
  const [keyset, updateKeySet] = useState(new KeySet());
  useEffect(() => {
    // we do this here to run on the client after the usercontext is populated
    if (userContext.user === null || userContext.user === "") {
      // redirect
      console.log("User is not logged in, redirecting.");
      redirect("/login");
      return;
    }
    const fetchKeybag = async () => {
      try {
        const resp = await fetch(`/api/keybag/${userContext.user}`, {
          credentials: "same-origin",
          headers: {
            "accept": "application/json",
          },
        });
        if (resp.status != 200) {
          console.log("error fetching keybag: ", resp.status);
          redirect("/login?error=fetch");
        }
        const body = await resp.json();
        const ks = await KeySet.fromKeybag(body, userContext.password);
        updateKeySet(ks);
      } catch(e) {
        console.log("error loading keybag", e);
        redirect("/login?error=load");
      }
    };
    fetchKeybag();
  }, [userContext.user, userContext.password]);
  const boxes: React.ReactNode[] = [];
  if (keyset) {
    keyset.getKeys().forEach((entry, i) => {
      boxes.push(
        <PasswordBox site={entry.site} username={entry.username} password={entry.password} key={'pw-'+i}></PasswordBox>
      );
    });
  }
  return (
    <div>
      {boxes}
    </div>
  );
}
