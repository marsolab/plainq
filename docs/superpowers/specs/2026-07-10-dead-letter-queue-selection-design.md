# Dead-Letter Queue Selection Design

## Status

Approved for written spec review.

## Context

Houston's queue creation dialog already sends `deadLetterQueueId` through the API client, but it does not expose a control for choosing that value. A user can select the Dead Letter eviction policy and submit a queue without selecting a destination queue.

The local preview also exposed an existing SQLite list failure: queues without a dead-letter queue store `dead_letter_queue_id` as `NULL`, while the dynamic list query scans that column directly into a Go string. Queue creation succeeds, but the following list refresh returns HTTP 500. The new selector depends on a reliable queue-list endpoint, so this regression is part of the feature scope.

## Goals

- Require a dead-letter queue when the Dead Letter eviction policy is selected.
- Let users choose any existing queue from the create-queue dialog.
- Let users create and fully configure a new dead-letter queue without leaving the parent dialog.
- Automatically select a newly created dead-letter queue.
- Prevent recursive dead-letter queue creation chains.
- Preserve the existing queue API contract.
- Fix SQLite queue listing for nullable dead-letter queue IDs.

## Non-Goals

- Creating the parent queue and its new dead-letter queue in one backend transaction.
- Deleting a newly created dead-letter queue when the parent dialog is cancelled or parent creation fails.
- Changing queue update or settings workflows.
- Adding queue search or a new server-side queue lookup endpoint.
- Allowing a newly created dead-letter queue to target another dead-letter queue from the nested flow.

## Interaction Design

The parent queue dialog keeps its current fields. When the eviction policy is not Dead Letter, no dead-letter queue control is shown and `deadLetterQueueId` is omitted from the request.

When Dead Letter is selected, a required **Dead-letter queue** field appears. Its dropdown contains:

- existing queues, displayed by queue name with queue ID as supporting text
- a **Create new queue** action
- loading, empty, and fetch-error states

Selecting an existing queue sets `deadLetterQueueId`. Choosing **Create new queue** opens a nested queue creation dialog above the parent dialog. The parent form and its entered values remain intact behind the nested dialog.

The nested dialog exposes the complete non-recursive queue configuration:

- queue name
- retention period
- visibility timeout
- maximum receive attempts
- eviction policy, excluding Dead Letter

After nested creation succeeds, the child dialog closes, the created queue is added to the local option list, and it becomes the selected dead-letter queue. The parent dialog remains open and requires its own submit action.

## Component Design

Extend `QueueCreateDialog` with an explicit mode rather than duplicating the form:

- parent mode retains the normal trigger and all eviction policies
- dead-letter mode uses the nested trigger, changes dialog copy as needed, and excludes the Dead Letter policy
- the creation callback returns both the created queue ID and the submitted queue name so the parent can add the option immediately without another list request

The parent mode owns dead-letter option loading and selected queue state. It renders a dead-letter-mode `QueueCreateDialog` only when the Dead Letter policy is active. The child mode cannot render another child dialog, which makes recursive creation structurally impossible.

Use the existing Base UI `Select` components for eviction policy and dead-letter queue selection. The nested dialog continues using the existing Base UI dialog primitives so focus trapping, keyboard dismissal, and portal stacking follow the application's current component conventions.

## Data Flow

### Selecting An Existing Queue

1. The parent dialog opens.
2. Houston requests queue pages with a page size of 100 and follows `nextCursor` until all current queue options are loaded.
3. The user selects Dead Letter, then selects an existing queue.
4. Parent submission sends the selected queue ID as `deadLetterQueueId`.

Pagination must stop if `hasMore` is false, the next cursor is empty, or a cursor repeats. This prevents an invalid server response from causing an infinite request loop.

### Creating A Dead-Letter Queue

1. The user selects Dead Letter and chooses **Create new queue**.
2. The nested dialog creates the child queue through the existing `POST /api/v1/queue` endpoint.
3. On success, Houston stores the returned queue ID and submitted name as a local option and selects it.
4. The user submits the parent dialog.
5. Houston creates the parent through the same endpoint with the child ID in `deadLetterQueueId`.

These are deliberately two independent requests. If the child succeeds and the parent is cancelled or fails, the child remains a normal queue. Houston must not imply rollback occurred.

## Validation

The create-queue schema conditionally requires `deadLetterQueueId` when `evictionPolicy` is `EVICTION_POLICY_DEAD_LETTER`.

Changing the parent policy away from Dead Letter clears the selected dead-letter queue before submission. The child form does not offer Dead Letter, so it never requires or sends `deadLetterQueueId`.

The existing numeric and naming validation remains unchanged in both modes.

## Error Handling

- If queue-option loading fails, show the error in the dead-letter field while keeping **Create new queue** available.
- If nested creation fails, keep both dialogs open and preserve both forms so the user can correct or retry.
- If nested creation succeeds, show a success toast indicating that the new queue was created and selected.
- If parent creation fails, keep the parent dialog open with the selected child queue and show the existing error toast.
- If the parent is cancelled after child creation, the child remains available in the queue list; no cleanup request is issued.
- Prevent parent submission while Dead Letter is selected without a valid queue ID.

## SQLite Regression Fix

The dynamic SQLite `listQueues` path must scan `dead_letter_queue_id` into `sql.NullString`, then assign its `.String` value to the protobuf response. This matches the sqlc-generated queue-property conversion already used elsewhere in the same storage package.

The storage schema remains nullable and no migration is required.

## Testing Strategy

Backend tests:

- create a queue without a dead-letter queue, list queues, and assert listing succeeds with an empty `deadLetterQueueId`
- retain coverage for a non-null dead-letter queue ID

Frontend tests:

- conditional validation requires a queue only for the Dead Letter policy
- changing away from Dead Letter omits the selected ID from the request
- queue-option pagination stops correctly and combines all pages
- child mode excludes the Dead Letter policy
- successful nested creation adds and selects the child option
- nested creation failure preserves the parent flow
- queue-option loading failure still exposes the create action

Verification:

- run Go tests and `golangci-lint`
- run Houston unit tests, type checks, and production build
- exercise the parent create flow with both an existing and newly created dead-letter queue in the local preview
- verify keyboard focus returns from the nested dialog to its trigger and that both dialogs fit mobile and desktop viewports
