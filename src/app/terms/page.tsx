import Link from 'next/link';
import { Contact, LegalDoc, LegalSection, List, P } from '@/components/legal/LegalDoc';
import { JURISDICTION, OPERATOR } from '@/lib/legal';

export const metadata = {
  title: 'Terms of service · OSINT Analyzer',
  description: 'The short terms for using OSINT Analyzer: a triage aid with no warranty, acceptable use, and Ontario law.',
};

export default function TermsPage() {
  return (
    <LegalDoc
      title="Terms of service"
      intro={<P>By using OSINT Analyzer, with or without an account, you agree to these terms. They are short on purpose.</P>}
    >
      <LegalSection id="what" title="What this is">
        <P>
          OSINT Analyzer looks up a link, email address, phone number, IP address or crypto wallet in public threat-intelligence
          sources and summarises what they say. It is run by {OPERATOR}. It is free to use.
        </P>
      </LegalSection>

      <LegalSection id="triage" title="A triage aid, not a guarantee">
        <P>
          A verdict is a starting point for your own judgement. Sources can be wrong, out of date, or not answer at all, and
          &ldquo;nothing found&rdquo; is not the same as &ldquo;safe&rdquo;. Don&apos;t rely on a result alone for a decision that
          matters: blocking a customer, sending money, or reporting someone.
        </P>
      </LegalSection>

      <LegalSection id="warranty" title="No warranty">
        <P>
          The service is provided &ldquo;as is&rdquo; and &ldquo;as available&rdquo;, without warranties of any kind. To the
          extent the law allows, {OPERATOR} is not liable for losses that come from using it, from relying on a result, or from it
          being unavailable.
        </P>
      </LegalSection>

      <LegalSection id="use" title="Acceptable use">
        <List>
          <li>Don&apos;t use it to harass, stalk or dox anyone, or to build profiles of private individuals.</li>
          <li>
            Don&apos;t use it to stress, scrape or get around the limits of the third-party sources it queries: no automated
            floods, no working around the per-hour limits, no splitting work across accounts.
          </li>
          <li>
            Respect each source&apos;s own terms. Keys you add in Settings are used under your agreement with that provider; the
            free tiers of several sources are for non-commercial use.
          </li>
          <li>Don&apos;t try to break, overload or get unauthorised access to the service or other people&apos;s accounts.</li>
        </List>
      </LegalSection>

      <LegalSection id="accounts" title="Accounts">
        <P>
          You are responsible for what happens under your account and for keeping your sign-in details safe. Accounts used for
          abuse, or in breach of these terms, can be limited, disabled or removed without notice. You can delete your own account
          at any time in <Link href="/settings#delete">Settings</Link>.
        </P>
      </LegalSection>

      <LegalSection id="privacy" title="Privacy">
        <P>
          How your data is handled is set out in the <Link href="/privacy">Privacy Policy</Link>.
        </P>
      </LegalSection>

      <LegalSection id="law" title="Changes and governing law">
        <P>
          These terms can change; the date at the top shows the latest version, and using the service after a change means you
          accept it. These terms are governed by the laws of {JURISDICTION}, and the courts of Ontario have jurisdiction over any
          dispute. Questions: <Contact />.
        </P>
      </LegalSection>
    </LegalDoc>
  );
}
