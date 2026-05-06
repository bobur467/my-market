# Security Specification for RQBMARKET

## Data Invariants
1. An ad cannot be created without a valid author.
2. Only admins can approve or reject ads.
3. Users can only edit or delete their own ads if they are still 'pending'. Once 'approved', they might need admin help to change critical info (to prevent bait-and-switch).
4. Reports can only be created by signed-in users.
5. Ratings can only be given once per buyer/seller pair (enforced by code, rules check existence).

## The Dirty Dozen Payloads (Rejection Tests)
1. Creating an ad with `status: "approved"` as a normal user.
2. Creating an ad with `userId` of another user.
3. Updating another user's ad.
4. Setting `price` as a negative number.
5. Injecting a massive string into the `title` field.
6. Deleting an admin-approved ad without admin rights.
7. Reading user private info (if any) as a stranger.
8. Self-assigning `role: "admin"` during profile creation.
9. Rating yourself (sellerId == buyerId).
10. Creating a report for a non-existent ad.
11. Updating `createdAt` timestamp.
12. Creating an ad with a 2MB base64 photo string (size limit check).

## Tests
Testing will be performed via manual verification against rules logic.
