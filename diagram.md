graph TD
  User[User submits email/phone/name] --> SF[SpiderFoot API Scan]
  SF --> Results{SpiderFoot results}
  Results -->|Linked email| DeHashed
  Results -->|Username found| DeHashed
  Results -->|IP found| Reputation check
  Results -->|Domain| Add to domain scan pool
  Results --> ExposureDB[(Supabase exposures)]
  ExposureDB --> UI[DataDrain frontend]