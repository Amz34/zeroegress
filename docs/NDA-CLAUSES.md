# NDA-ready clauses

Drafting notes, not legal advice. Have a lawyer review before signature. These
clauses are written so that each one is *checkable* — every commitment maps to a
command in [AUDIT-GUIDE.md](AUDIT-GUIDE.md).

## 1. Scope of confidential information

> "Confidential Information" means all non-public information disclosed by the
> Client to the Supplier in any form, including tender documents, bills of
> quantities, pricing schedules, drawings, specifications, correspondence, and any
> derivative notes, summaries, or extracts prepared by the Supplier.

*Why:* "derivative notes" is the clause most often missing, and it is exactly what
an AI workflow produces.

## 2. Processing location and permitted systems

> The Supplier shall process Confidential Information only on systems under its
> sole control. Confidential Information shall not be submitted to any
> third-party hosted artificial-intelligence, translation, transcription, or
> document-conversion service, whether free or paid, without the Client's prior
> written consent.

## 3. No training, no secondary use

> The Supplier shall not use Confidential Information, or any derivative of it, to
> train, fine-tune, evaluate, or otherwise improve any machine-learning model, and
> shall not disclose it to any party for that purpose.

## 4. Encryption at rest and key custody

> Archives containing Confidential Information shall be encrypted with AES-256 or
> stronger. Where the Client elects to hold its own key, the Supplier shall retain
> no copy of that key for the encrypted archive containing the Client's documents.

## 5. Segregation between clients

> The Supplier shall keep Confidential Information of each client in a separate
> encrypted store with a separate key, and shall not co-mingle it with the data of
> any other client in a shared index, folder, or account.

## 6. Sub-processors

> The Supplier shall list all sub-processors that may access Confidential
> Information, and shall notify the Client at least 14 days before adding one. The
> current list is attached as Schedule 1.

## 7. Retention and deletion

> The Supplier shall retain Confidential Information for no longer than the
> engagement plus [5] days, after which it shall be deleted from primary storage
> and, subject to the backup retention window stated in Schedule 1, from backups.
> On written request the Supplier shall delete it earlier and confirm deletion in
> writing within 5 business days.

## 8. Breach notification

> The Supplier shall notify the Client without undue delay and in any event within
> 72 hours of becoming aware of any unauthorised access to, or disclosure of,
> Confidential Information, and shall provide the information reasonably required
> for the Client's own regulatory notifications.

## 9. Audit and verification

> On reasonable notice, not more than once per 12 months, the Supplier shall allow
> the Client to verify the controls described in this agreement by running the
> verification steps published with the Supplier's tooling, in the presence of the
> Supplier's personnel if requested.

## 10. Return or destruction on termination

> On termination the Supplier shall return or destroy Confidential Information at
> the Client's direction, and shall certify in writing that no copy remains in
> primary storage.

## Schedule 1 — to be completed before signature

| Item | Value |
|------|-------|
| Processing location (country/region) | |
| Sub-processors (name, purpose, data touched) | |
| Backup retention window | |
| Encryption standard and key owner | |
| Named contact for breach notice | |
| Maximum audit frequency | |
